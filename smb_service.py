#!/usr/bin/env python3
"""
SMB File Service
A Python service for uploading and downloading files via SMB with signing support.
"""

import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
import argparse
import json

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not found. Install with: pip install python-dotenv")
    print("Environment variables will be loaded from system environment only.")

try:
    import smbclient
    from smbclient import ClientConfig
except ImportError:
    print("Error: smbprotocol library not found. Install with: pip install smbprotocol")
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SMBConfig:
    """SMB connection configuration"""
    server: str
    share: str
    username: str
    password: str
    domain: str = ""
    port: int = 445
    require_signing: bool = True
    encrypt: bool = False
    timeout: int = 30

class SMBFileService:
    """SMB File Service for upload/download operations"""
    
    def __init__(self, config: SMBConfig):
        self.config = config
        self.server_url = f"//{config.server}/{config.share}"
        self._setup_client_config()
    
    def _setup_client_config(self):
        """Configure SMB client with security settings"""
        try:
            # Format username with domain if provided
            username = self.config.username
            if self.config.domain:
                username = f"{self.config.domain}\\{self.config.username}"
            
            # Register the server session with authentication
            smbclient.register_session(
                server=self.config.server,
                username=username,
                password=self.config.password,
                port=self.config.port,
                encrypt=self.config.encrypt,
                connection_timeout=self.config.timeout
            )
            
            # Configure client settings for signing
            ClientConfig().require_signing = self.config.require_signing
            
            logger.info(f"SMB session registered for {self.config.server}")
            logger.info(f"SMB signing required: {self.config.require_signing}")
            logger.info(f"Username format: {username}")
            
        except Exception as e:
            logger.error(f"Failed to setup SMB client: {e}")
            raise
    
    def upload_file(self, local_path: str, remote_path: str, 
                   create_dirs: bool = True) -> Dict[str, Any]:
        """
        Upload a file to SMB share
        
        Args:
            local_path: Path to local file
            remote_path: Path on SMB share (relative to share root)
            create_dirs: Create remote directories if they don't exist
            
        Returns:
            Dictionary with upload status and metadata
        """
        try:
            local_file = Path(local_path)
            if not local_file.exists():
                raise FileNotFoundError(f"Local file not found: {local_path}")
            
            # Construct full remote path
            full_remote_path = f"{self.server_url}/{remote_path.lstrip('/')}"
            
            # Create remote directories if needed
            if create_dirs:
                remote_dir = str(Path(full_remote_path).parent)
                self._ensure_remote_dir(remote_dir)
            
            # Upload file
            logger.info(f"Uploading {local_path} to {full_remote_path}")
            
            with open(local_file, 'rb') as local_f:
                with smbclient.open_file(full_remote_path, mode='wb') as remote_f:
                    # Copy file in chunks for better performance
                    chunk_size = 64 * 1024  # 64KB chunks
                    while True:
                        chunk = local_f.read(chunk_size)
                        if not chunk:
                            break
                        remote_f.write(chunk)
            
            # Get file info for verification
            file_size = local_file.stat().st_size
            
            logger.info(f"Upload completed: {file_size} bytes")
            
            return {
                'status': 'success',
                'local_path': str(local_file),
                'remote_path': full_remote_path,
                'size_bytes': file_size,
                'message': 'File uploaded successfully'
            }
            
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return {
                'status': 'error',
                'local_path': local_path,
                'remote_path': remote_path,
                'error': str(e)
            }
    
    def download_file(self, remote_path: str, local_path: str,
                     overwrite: bool = False) -> Dict[str, Any]:
        """
        Download a file from SMB share
        
Args:
            remote_path: Path on SMB share (relative to share root)
            local_path: Local destination path
            overwrite: Overwrite local file if it exists
            
        Returns:
            Dictionary with download status and metadata
        """
        try:
            local_file = Path(local_path)
            
            # Check if local file exists
            if local_file.exists() and not overwrite:
                raise FileExistsError(f"Local file exists and overwrite=False: {local_path}")
            
            # Create local directory if needed
            local_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Construct full remote path
            full_remote_path = f"{self.server_url}/{remote_path.lstrip('/')}"
            
            # Check if remote file exists
            if not smbclient.path.exists(full_remote_path):
                raise FileNotFoundError(f"Remote file not found: {full_remote_path}")
            
            # Download file
            logger.info(f"Downloading {full_remote_path} to {local_path}")
            
            with smbclient.open_file(full_remote_path, mode='rb') as remote_f:
                with open(local_file, 'wb') as local_f:
                    # Copy file in chunks
                    chunk_size = 64 * 1024  # 64KB chunks
                    total_size = 0
                    while True:
                        chunk = remote_f.read(chunk_size)
                        if not chunk:
                            break
                        local_f.write(chunk)
                        total_size += len(chunk)
            
            logger.info(f"Download completed: {total_size} bytes")
            
            return {
                'status': 'success',
                'remote_path': full_remote_path,
                'local_path': str(local_file),
                'size_bytes': total_size,
                'message': 'File downloaded successfully'
            }
            
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return {
                'status': 'error',
                'remote_path': remote_path,
                'local_path': local_path,
                'error': str(e)
            }
    
    def list_files(self, remote_path: str = "") -> Dict[str, Any]:
        """
        List files in remote directory
        
        Args:
            remote_path: Remote directory path (relative to share root)
            
        Returns:
            Dictionary with file listing
        """
        try:
            full_remote_path = f"{self.server_url}/{remote_path.lstrip('/')}"
            
            logger.info(f"Listing files in {full_remote_path}")
            
            files = []
            for entry in smbclient.listdir(full_remote_path):
                entry_path = f"{full_remote_path}/{entry}"
                try:
                    stat_info = smbclient.stat(entry_path)
                    files.append({
                        'name': entry,
                        'size': stat_info.st_size,
                        'is_dir': smbclient.path.isdir(entry_path),
                        'modified': stat_info.st_mtime
                    })
                except Exception as e:
                    logger.warning(f"Could not stat {entry}: {e}")
                    files.append({
                        'name': entry,
                        'error': str(e)
                    })
            
            return {
                'status': 'success',
                'path': full_remote_path,
                'files': files,
                'count': len(files)
            }
            
        except Exception as e:
            logger.error(f"List files failed: {e}")
            return {
                'status': 'error',
                'path': remote_path,
                'error': str(e)
            }
    
    def _ensure_remote_dir(self, remote_dir_path: str):
        """Create remote directory if it doesn't exist"""
        try:
            if not smbclient.path.exists(remote_dir_path):
                smbclient.makedirs(remote_dir_path)
                logger.info(f"Created remote directory: {remote_dir_path}")
        except Exception as e:
            logger.warning(f"Could not create remote directory {remote_dir_path}: {e}")
    
    def test_connection(self) -> Dict[str, Any]:
        """Test SMB connection and signing status"""
        try:
            # Try to list the root directory
            result = smbclient.listdir(self.server_url)
            
            return {
                'status': 'success',
                'server': self.config.server,
                'share': self.config.share,
                'signing_required': self.config.require_signing,
                'connection': 'active',
                'message': f'Connected successfully. Found {len(result)} items in root.'
            }
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return {
                'status': 'error',
                'server': self.config.server,
                'share': self.config.share,
                'error': str(e)
            }
    
    def close(self):
        """Clean up SMB session"""
        try:
            # The smbclient handles session cleanup automatically
            logger.info("SMB session cleanup completed")
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")

def load_config_from_env() -> SMBConfig:
    """Load configuration from environment variables"""
    try:
        config = SMBConfig(
            server=os.getenv('SMB_SERVER', ''),
            share=os.getenv('SMB_SHARE', ''),
            username=os.getenv('SMB_USERNAME', ''),
            password=os.getenv('SMB_PASSWORD', ''),
            domain=os.getenv('SMB_DOMAIN', ''),
            port=int(os.getenv('SMB_PORT', '445')),
            require_signing=os.getenv('SMB_REQUIRE_SIGNING', 'true').lower() == 'true',
            encrypt=os.getenv('SMB_ENCRYPT', 'false').lower() == 'true',
            timeout=int(os.getenv('SMB_TIMEOUT', '30'))
        )
        
        # Validate required fields
        if not all([config.server, config.share, config.username, config.password]):
            raise ValueError("Missing required environment variables: SMB_SERVER, SMB_SHARE, SMB_USERNAME, SMB_PASSWORD")
        
        return config
    except Exception as e:
        logger.error(f"Failed to load config from environment: {e}")
        raise

def load_config_from_file(config_file: str) -> SMBConfig:
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        return SMBConfig(**config_data)
    except Exception as e:
        logger.error(f"Failed to load config from {config_file}: {e}")
        raise

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='SMB File Service')
    parser.add_argument('--config', '-c', help='Configuration file (JSON)')
    parser.add_argument('--env', action='store_true', help='Load configuration from environment variables')
    parser.add_argument('--server', help='SMB server address')
    parser.add_argument('--share', help='SMB share name')
    parser.add_argument('--username', '-u', help='Username')
    parser.add_argument('--password', '-p', help='Password')
    parser.add_argument('--domain', '-d', default='', help='Domain')
    parser.add_argument('--no-signing', action='store_true', help='Disable SMB signing')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload file')
    upload_parser.add_argument('local_path', help='Local file path')
    upload_parser.add_argument('remote_path', help='Remote file path')
    upload_parser.add_argument('--no-create-dirs', action='store_true', 
                              help='Do not create remote directories')
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Download file')
    download_parser.add_argument('remote_path', help='Remote file path')
    download_parser.add_argument('local_path', help='Local file path')
    download_parser.add_argument('--overwrite', action='store_true', 
                                help='Overwrite local file if exists')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List remote files')
    list_parser.add_argument('remote_path', nargs='?', default='', 
                            help='Remote directory path')
    
    # Test command
    subparsers.add_parser('test', help='Test connection')
    
    args = parser.parse_args()
    
    # Load configuration
    if args.env:
        config = load_config_from_env()
    elif args.config:
        config = load_config_from_file(args.config)
    else:
        if not all([args.server, args.share, args.username, args.password]):
            parser.error("Must provide either --env, --config file, or server/share/username/password")
        
        config = SMBConfig(
            server=args.server,
            share=args.share,
            username=args.username,
            password=args.password,
            domain=args.domain,
            require_signing=not args.no_signing
        )
    
    # Create service
    service = SMBFileService(config)
    
    try:
        # Execute command
        if args.command == 'upload':
            result = service.upload_file(
                args.local_path, 
                args.remote_path,
                create_dirs=not args.no_create_dirs
            )
        elif args.command == 'download':
            result = service.download_file(
                args.remote_path,
                args.local_path,
                overwrite=args.overwrite
            )
        elif args.command == 'list':
            result = service.list_files(args.remote_path)
        elif args.command == 'test':
            result = service.test_connection()
        else:
            parser.print_help()
            return
        
        # Print result
        print(json.dumps(result, indent=2))
        
        # Exit with error code if operation failed
        if result.get('status') == 'error':
            exit(1)
            
    finally:
        service.close()

if __name__ == '__main__':
    main()