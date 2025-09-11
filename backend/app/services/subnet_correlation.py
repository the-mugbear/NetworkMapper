from typing import List
from sqlalchemy.orm import Session
from app.db.models import Host, Subnet, HostSubnetMapping, HostScanHistory
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
        # Get hosts discovered by this scan using audit table
        hosts = self.db.query(Host).join(HostScanHistory, Host.id == HostScanHistory.host_id).filter(HostScanHistory.scan_id == scan_id).all()
        
        total_mappings = 0
        for host in hosts:
            mappings = self.correlate_host_to_subnets(host)
            total_mappings += len(mappings)
        
        return total_mappings

    def batch_correlate_scan_hosts_to_subnets(self, scan_id: int) -> int:
        """
        Batch correlate all hosts from a specific scan to their respective subnets.
        Uses efficient IP trie for O(log n) lookup time per host.
        
        Args:
            scan_id: The scan ID to process
            
        Returns:
            Number of mappings created
        """
        # Get all hosts from the scan
        hosts = self.db.query(Host).join(HostScanHistory, Host.id == HostScanHistory.host_id).filter(HostScanHistory.scan_id == scan_id).all()
        if not hosts:
            return 0
        
        # Check if we have any subnets to match against
        subnet_count = self.db.query(Subnet).count()
        if subnet_count == 0:
            return 0
        
        # Clear existing mappings for all hosts in this scan
        host_ids = [host.id for host in hosts]
        self.db.query(HostSubnetMapping).filter(
            HostSubnetMapping.host_id.in_(host_ids)
        ).delete()
        
        # Use trie-based lookup for efficient matching
        # The parser's find_matching_subnets method now uses the cached trie
        mapping_data = []
        for host in hosts:
            matching_subnets = self.parser.find_matching_subnets(host.ip_address)
            
            for subnet in matching_subnets:
                mapping_data.append({
                    'host_id': host.id,
                    'subnet_id': subnet.id
                })
        
        # Bulk insert all mappings
        if mapping_data:
            self.db.bulk_insert_mappings(HostSubnetMapping, mapping_data)
            self.db.commit()
        
        return len(mapping_data)
    
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
    
    def invalidate_subnet_cache(self):
        """Invalidate the subnet trie cache. Call after subnet modifications."""
        self.parser.invalidate_trie_cache()
    
    def get_performance_stats(self) -> dict:
        """Get performance statistics about the subnet matching system."""
        return {
            'total_subnets': self.db.query(Subnet).count(),
            'total_mappings': self.db.query(HostSubnetMapping).count(),
            'trie_stats': self.parser.get_trie_stats()
        }