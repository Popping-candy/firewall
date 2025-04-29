#ifndef _TOOL_H
#define _TOOL_H

int log(struct sk_buff *skb, bool action);
int print_pkg(struct sk_buff *skb);

bool packetHandler(struct sk_buff *skb);
bool matchRule(Packet aPacket, bool *isInLog);
bool findInConnection(Packet aPacket);
void addConnection(Packet aPacket);
int hash(Packet aPacket);
void time_handler(unsigned long x);
#endif