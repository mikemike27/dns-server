import socket
import struct


def build_dns_query(domain_name, qtype):
    """Build a DNS query for a given domain and query type."""
    qname = encode_domain_name(domain_name)
    qtype_bytes = (qtype).to_bytes(2, 'big')  # Query type (A = 1, CNAME = 5)
    qclass_bytes = (1).to_bytes(2, 'big')  # Query class (IN = 1)

    # Transaction ID (use a fixed value or generate randomly if needed)
    transaction_id = b'\x00\x01'

    # Flags (standard query, no special flags)
    flags = b'\x01\x00'  # Standard query with recursion desired

    # Number of questions, answers, authority, and additional sections
    qdcount = (1).to_bytes(2, 'big')  # Number of questions
    ancount = (0).to_bytes(2, 'big')  # Number of answers
    nscount = (0).to_bytes(2, 'big')  # Number of authority records
    arcount = (0).to_bytes(2, 'big')  # Number of additional records

    return (
            transaction_id +  # Transaction ID
            flags +  # Flags
            qdcount +  # Number of questions
            ancount +  # Number of answers
            nscount +  # Number of authority records
            arcount +  # Number of additional records
            qname + qtype_bytes + qclass_bytes  # Question section
    )


def encode_domain_name(domain):
    """Encode a domain name in DNS label format."""
    labels = domain.strip('.').split('.')
    encoded = b''

    for label in labels:
        length = len(label)
        encoded += bytes([length])  # Add length byte
        encoded += label.encode()  # Add label bytes

    encoded += b'\x00'  # End of domain name
    return encoded


def parse_domain_name(data, offset):
    """Parse a domain name from DNS response starting at a given offset."""
    labels = []
    length = data[offset]
    while length > 0:
        labels.append(data[offset + 1:offset + 1 + length].decode())
        offset += length + 1
        length = data[offset]
    return '.'.join(labels), offset + 1


def parse_dns_response(response):
    """Parse the DNS response from the server and return formatted details."""
    transaction_id = response[:2].hex()
    flags = response[2:4].hex()
    qcount = int.from_bytes(response[4:6], 'big')
    acount = int.from_bytes(response[6:8], 'big')

    offset = 12  # Skip the DNS header
    # Parse question section
    domain_name, offset = parse_domain_name(response, offset)
    qtype, qclass = struct.unpack('>HH', response[offset:offset + 4])
    offset += 4

    results = []
    for _ in range(acount):
        offset += 2
        rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset + 10])
        offset += 10
        rdata = response[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1:  # A record
            ip_address = '.'.join(map(str, rdata))
            results.append((domain_name, 'A', ttl, 'Answer', ip_address))
        elif rtype == 5:  # CNAME record
            cname, _ = parse_domain_name(response, offset - rdlength)
            results.append((domain_name, 'CNAME', ttl, 'Answer', cname))

    return results


def main():
    server_ip = '127.0.0.1'
    server_port = 53

    while True:
        # Get hostname from user
        domain_name = input("Enter the hostname to query (e.g., example.com): ").strip()
        if not domain_name:
            print("Invalid input. Exiting...")
            break

        # Get record type from user
        record_type = input("Enter the record type to query (A for Type A, CNAME for Type CNAME): ").strip().upper()
        if record_type == 'A':
            qtype = 1
        elif record_type == 'CNAME':
            qtype = 5
        else:
            print("Invalid record type. Please enter 'A' or 'CNAME'.")
            continue

        # Create UDP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Build DNS query
        query = build_dns_query(domain_name, qtype)

        try:
            # Send query to server
            client_socket.sendto(query, (server_ip, server_port))

            # Receive response from server
            response, _ = client_socket.recvfrom(512)

            # Parse and display response
            results = parse_dns_response(response)
            print(f"\nResponse Details:")
            if results:
                for name, rtype, ttl, section, value in results:
                    print(f"Name: {name}")
                    print(f"Type: {rtype}")
                    print(f"TTL: {ttl}")
                    print(f"Section: {section}")
                    print(f"Value: {value}\n")
            else:
                print("No records found in the response.")

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            client_socket.close()

        # Ask if user wants to continue
        continue_query = input("Do you want to perform another DNS query? (yes/no): ").strip().lower()
        if continue_query != 'yes':
            print("Exiting...")
            break


if __name__ == "__main__":
    main()
