import ipaddress
from typing import List, Tuple
from sqlalchemy.orm import Session
from app.db.models import Scope, Subnet

class SubnetParser:
    def __init__(self, db: Session):
        self.db = db
    
    def parse_subnet_file(self, file_content: str, scope_name: str, scope_description: str = None) -> Tuple[Scope, int]:
        """
        Parse a subnet file and create a scope with subnets.
        
        Args:
            file_content: Content of the subnet file
            scope_name: Name for the new scope
            scope_description: Optional description for the scope
            
        Returns:
            Tuple of (Scope object, number of subnets added)
        """
        lines = file_content.strip().split('\n')
        valid_subnets = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
                
            try:
                # Validate CIDR notation
                network = ipaddress.ip_network(line, strict=False)
                valid_subnets.append(str(network))
            except ValueError as e:
                raise ValueError(f"Invalid subnet on line {line_num}: '{line}' - {str(e)}")
        
        if not valid_subnets:
            raise ValueError("No valid subnets found in file")
        
        # Create scope
        scope = Scope(
            name=scope_name,
            description=scope_description
        )
        self.db.add(scope)
        self.db.flush()  # Get the scope ID
        
        # Add subnets
        for subnet_cidr in valid_subnets:
            subnet = Subnet(
                scope_id=scope.id,
                cidr=subnet_cidr
            )
            self.db.add(subnet)
        
        self.db.commit()
        return scope, len(valid_subnets)
    
    def validate_subnet(self, cidr: str) -> bool:
        """Validate a single subnet CIDR notation."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    def ip_in_subnet(self, ip_address: str, cidr: str) -> bool:
        """Check if an IP address belongs to a subnet."""
        try:
            ip = ipaddress.ip_address(ip_address)
            network = ipaddress.ip_network(cidr, strict=False)
            return ip in network
        except ValueError:
            return False
    
    def find_matching_subnets(self, ip_address: str) -> List[Subnet]:
        """Find all subnets that contain the given IP address."""
        matching_subnets = []
        subnets = self.db.query(Subnet).all()
        
        for subnet in subnets:
            if self.ip_in_subnet(ip_address, subnet.cidr):
                matching_subnets.append(subnet)
        
        return matching_subnets

    def get_all_subnets(self) -> List[Subnet]:
        """Get all subnets from the database."""
        return self.db.query(Subnet).all()

    def find_matching_subnets_from_list(self, ip_address: str, subnets: List[Subnet]) -> List[Subnet]:
        """Find matching subnets from a pre-loaded list (more efficient for batch operations)."""
        matching_subnets = []
        
        for subnet in subnets:
            if self.ip_in_subnet(ip_address, subnet.cidr):
                matching_subnets.append(subnet)
        
        return matching_subnets