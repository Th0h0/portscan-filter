import nmap
import regex
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", type=str, required=True, help= 'file of all domains and ports to filter')
parser.add_argument("--output2", "-p", type=str, required=False, help='problematic domain output file path')
parser.add_argument("--output1", "-o", type=str, required=False, help='domains without problematic')


args = parser.parse_args()

THRESHOLD = 3500

def get_hostname(domain):
    hostRegex = "(.*)(?=:)"
    hostNameContainer = regex.search(hostRegex,domain)

    if hostNameContainer:
        return hostNameContainer[0]
    else:
        return None

def detect_problematic_domains(subsList, outputFile2):

    domain_dict = {}
    problematic_domains = []

    for domain in subsList:

        if ':' not in domain:
            continue

        domainHost = get_hostname(domain)

        if domain_dict.get(domainHost):
            domain_dict[domainHost] += 1
            if domain_dict[domainHost] == THRESHOLD:
                problematic_domains.append(domainHost)
        else:
            domain_dict[domainHost] = 1

    for pd in problematic_domains:
        outputFile2.write(f"{pd}\n")

    return problematic_domains

def write_output(subsList, problematic_domains, outputFile1):
    for domain in subsList:
        if ':' not in domain:
            outputFile1.write(domain)
            continue

        domainHost = get_hostname(domain)

        if domainHost not in problematic_domains:
            outputFile1.write(domain)

def fiter_port_scan(subsList):

    if args.output1:
        outputFile1 = open(args.output1, "w")
    else:
        outputFile1 = open("portscan-filter-output.txt", "w")

    if args.output2:
        outputFile2 = open(args.output2, "w")
    else:
        outputFile2 = open("problematic-domain-output.txt", "w")

    problematic_domains = detect_problematic_domains(subsList, outputFile2)
    write_output(subsList, problematic_domains, outputFile1)

    outputFile1.close()
    outputFile2.close()

def main():
    domainListStream = open(args.file, "r")
    domainList = [domain for domain in domainListStream]

    fiter_port_scan(domainList)

    domainListStream.close()

if __name__ == '__main__':
    main()
