from typing import List
from sqlalchemy.orm import Session
from app.db.models import Host, Subnet, HostSubnetMapping
from app.parsers.subnet_parser import SubnetParser

class SubnetCorrelationService:
    def __init__(self, db: Session):
        self.db = db
        self.parser = SubnetParser(db)
    
    def correlate_host_to_subnets(self, host: Host) -> List[HostSubnetMapping]:
        """
        Find and create mappings between a host and all subnets it belongs to.
        
        Args:
            host: The host to correlate
            
        Returns:
            List of created HostSubnetMapping objects
        """
        # Clear existing mappings for this host
        self.db.query(HostSubnetMapping).filter(
            HostSubnetMapping.host_id == host.id
        ).delete()
        
        # Find matching subnets
        matching_subnets = self.parser.find_matching_subnets(host.ip_address)
        
        # Create new mappings
        mappings = []
        for subnet in matching_subnets:
            mapping = HostSubnetMapping(
                host_id=host.id,
                subnet_id=subnet.id
            )
            self.db.add(mapping)
            mappings.append(mapping)
        
        self.db.commit()
        return mappings
    
    def correlate_all_hosts_to_subnets(self) -> int:
        """
        Correlate all existing hosts to their respective subnets.
        
        Returns:
            Number of mappings created
        """
        # Clear all existing mappings
        self.db.query(HostSubnetMapping).delete()
        
        # Get all hosts
        hosts = self.db.query(Host).all()
        
        total_mappings = 0
        for host in hosts:
            mappings = self.correlate_host_to_subnets(host)
            total_mappings += len(mappings)
        
        return total_mappings
    
    def correlate_scan_hosts_to_subnets(self, scan_id: int) -> int:
        """
        Correlate all hosts from a specific scan to their respective subnets.
        
        Args:
            scan_id: The scan ID to process
            
        Returns:
            Number of mappings created
        """
        hosts = self.db.query(Host).filter(Host.scan_id == scan_id).all()
        
        total_mappings = 0
        for host in hosts:
            mappings = self.correlate_host_to_subnets(host)
            total_mappings += len(mappings)
        
        return total_mappings
    
    def get_host_subnets(self, host_id: int) -> List[Subnet]:
        """
        Get all subnets that a host belongs to.
        
        Args:
            host_id: The host ID
            
        Returns:
            List of Subnet objects
        """
        mappings = self.db.query(HostSubnetMapping).filter(
            HostSubnetMapping.host_id == host_id
        ).all()
        
        return [mapping.subnet for mapping in mappings]
    
    def get_subnet_hosts(self, subnet_id: int) -> List[Host]:
        """
        Get all hosts that belong to a specific subnet.
        
        Args:
            subnet_id: The subnet ID
            
        Returns:
            List of Host objects
        """
        mappings = self.db.query(HostSubnetMapping).filter(
            HostSubnetMapping.subnet_id == subnet_id
        ).all()
        
        return [mapping.host for mapping in mappings]