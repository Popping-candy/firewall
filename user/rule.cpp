#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdint.h>

struct FirewallRule
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    bool action;
};

uint32_t IPstr2IPint(const std::string &ipStr)
{
    std::vector<int> ipParts;
    std::stringstream ss(ipStr);
    std::string token;
    char delimiter = '.';
    while (std::getline(ss, token, delimiter))
    {
        ipParts.push_back(std::stoi(token));
    }
    if (ipParts.size() != 4)
    {
        std::cerr << "Invalid IP address format." << std::endl;
        return 0;
    }

    uint32_t ipInt = 0;
    for (int i = 0; i < 4; ++i)
    {
        if (ipParts[i] < 0 || ipParts[i] > 255)
        {
            std::cerr << "Invalid IP address format." << std::endl;
            return 0;
        }

        ipInt |= (ipParts[i] << (8 * (3 - i)));
    }

    return ipInt;
}
std::vector<FirewallRule> readRulesFromFile(const std::string &filename)
{
    std::vector<FirewallRule> rules;
    std::ifstream file(filename.c_str());

    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return rules;
    }

    std::string line;
    std::string sipStr, dipStr;
    char buffer1[20];
    char buffer2[20];
    while (std::getline(file, line))
    {
        FirewallRule rule;
        if (sscanf(line.c_str(), "%s %s %hu %hu %hhu %d", buffer1, buffer2, &rule.src_port, &rule.dst_port, &rule.protocol, &rule.action) == 6)
        {
            sipStr = buffer1;
            dipStr = buffer2;
            rule.src_ip = IPstr2IPint(sipStr);
            rule.dst_ip = IPstr2IPint(dipStr);
            rules.push_back(rule);
        }
        else
        {
            std::cerr << "Invalid format in line: " << line << std::endl;
        }
    }

    file.close();
    return rules;
}

void printRules(const std::vector<FirewallRule> &rules)
{
    int index = 1;
    for (std::vector<FirewallRule>::const_iterator it = rules.begin(); it != rules.end(); ++it)
    {
        const FirewallRule &rule = *it;
        std::cout << "Index: " << index++
                  << ", SrcIP: " << rule.src_ip << ", dst_ip: " << rule.dst_ip
                  << ", SrcPort: " << rule.src_port << ", dst_port: " << rule.dst_port
                  << ", Protocol: " << rule.protocol << ", Action: " << rule.action
                  << std::endl;
    }
}

void addRule(std::vector<FirewallRule> &rules, int index, const FirewallRule &rule)
{
    if (index >= 0 && index <= rules.size())
    {
        rules.insert(rules.begin() + index, rule);
        std::cout << "Rule added successfully." << std::endl;
    }
    else
    {
        std::cerr << "Invalid index. Rule not added." << std::endl;
    }
}

void removeRule(std::vector<FirewallRule> &rules, int index)
{
    if (index >= 0 && index < rules.size())
    {
        rules.erase(rules.begin() + index);
        std::cout << "Rule removed successfully." << std::endl;
    }
    else
    {
        std::cerr << "Invalid index. Rule not removed." << std::endl;
    }
}

void modifyRule(std::vector<FirewallRule> &rules, int index, const FirewallRule &newRule)
{
    if (index >= 0 && index < rules.size())
    {
        rules[index] = newRule;
        std::cout << "Rule modified successfully." << std::endl;
    }
    else
    {
        std::cerr << "Invalid index. Rule not modified." << std::endl;
    }
}

int main()
{

    std::string filename = "data/rules.txt";

    std::vector<FirewallRule> rules = readRulesFromFile(filename);

    std::string userInput;
    while (true)
    {
        std::cout << "Enter command ('add', 'remove', 'modify', 'view', or 'exit'): ";
        std::cin >> userInput;

        if (userInput == "add")
        {
            int index;
            FirewallRule newRule;

            std::cout << "Enter index to add the rule: ";
            std::cin >> index;

            std::cout << "Enter source IP: ";
            std::cin >> newRule.src_ip;

            std::cout << "Enter destination IP: ";
            std::cin >> newRule.dst_ip;

            std::cout << "Enter source port: ";
            std::cin >> newRule.src_port;

            std::cout << "Enter destination port: ";
            std::cin >> newRule.dst_port;

            std::cout << "Enter protocol: ";
            std::cin >> newRule.protocol;

            std::cout << "Enter action (0/1): ";
            std::cin >> newRule.action;

            addRule(rules, index, newRule);
        }
        else if (userInput == "remove")
        {
            int index;
            std::cout << "Enter index to remove the rule: ";
            std::cin >> index;

            removeRule(rules, index);
        }
        else if (userInput == "modify")
        {
            int index;
            FirewallRule newRule;

            std::cout << "Enter index to modify the rule: ";
            std::cin >> index;

            std::cout << "Enter new source IP: ";
            std::cin >> newRule.src_ip;

            std::cout << "Enter new destination IP: ";
            std::cin >> newRule.dst_ip;

            std::cout << "Enter new source port: ";
            std::cin >> newRule.src_port;

            std::cout << "Enter new destination port: ";
            std::cin >> newRule.dst_port;

            std::cout << "Enter new protocol: ";
            std::cin >> newRule.protocol;

            std::cout << "Enter new action (0/1): ";
            std::cin >> newRule.action;

            modifyRule(rules, index, newRule);
        }
        else if (userInput == "view")
        {
            printRules(rules);
        }
        else if (userInput == "exit")
        {
            break;
        }
        else
        {
            std::cout << "Invalid command. Please try again." << std::endl;
        }
    }

    return 0;
}
