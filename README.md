# pano
Panorama configuration analyzer. Requires either access to panorama via SSH, or just plain text file with config in "set" output format, by default pano_current.txt. The project is in about 60% of progress, altough here should be the last WORKING script (completing work, with all errors captured). 

Input parameters are optional: IP address of Panorama, username and password. 

The output is either to the console (mostly warnings and errors about the script itself), or to the files. 


Most important output files are: 

I_reverse_lex.txt - reverse dictionary. IPs, hostnames, and their related object names, count of references in brackets. Useful for finding duplicates. 

I_devices_membership.txt - device serials and their assignments to DeviceGroups and Templaes (via template stacks)

I_object_count.txt - device groups and objects, with reference counters. Useful for finding not used objects. 

E_bad_rules - rules with source or destination IPs, not matching zone IPs and routes coming out via these zones. 

W_routes_errors.txt - routes with possible errors (like default gateway not reachable). 

W_rules_with_empty_zones - security rules with src/dst zones that either has no interfaces assigned, or these interfaces have no IPs. 

I_rules2.txt - security rules "unwrapped" - objects are replaced by their values, even if they were groups. 

W_mismatch_name_and_content - objects that their name suggest different content (like IP)

I_devices_IPs.txt - devices with their allocated IP addresses. 

W_unmatched_lines - lines unmatched by any regex. 

I_zones_interfaces_IPs.txt - IPs assigned to specific zones in templates. 

I_zones_routes.txt - routes going out via specific zones. 

I_fqdn_objects - fqdn objects and their IP resolution. Useful for finding bad FQDNs. 

E_services_broken - services with source ports different than 1024:65535. 99% of these cases are human errors. 

E_rules_with_missing_attributes.txt - rules with some atributes missing, like containing no sources (not "any"!) or no service. 


More to come. 
