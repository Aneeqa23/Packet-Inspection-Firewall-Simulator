#include <iostream>
#include <string>
#include <sstream>
using namespace std;

//////////////////////////////////////////////////////
//                 PACKET SYSTEM                   //
//////////////////////////////////////////////////////

struct Packet {
    int id;
    string sourceIP;
    string protocol;
    int port;
    int riskScore;
    Packet* next;   
};

int packetCounter = 0;

Packet createPacket() {
    Packet p;
    p.id = ++packetCounter;
    p.next = NULL;

    cout << "\n--- CREATE PACKET ---\n";

    cout << "Source IP: ";
    cin >> p.sourceIP;

    while (true) {
        cout << "Protocol (HTTP/DNS/FTP/SSH): ";
        cin >> p.protocol;

        if (p.protocol == "HTTP" || p.protocol == "DNS" ||
            p.protocol == "FTP"  || p.protocol == "SSH") {
            break;
        }
        cout << "Invalid Protocol! Try again.\n";
    }

    while (true) {
        cout << "Port
		: ";
        cin >> p.port;

        if (cin.fail() || p.port < 0 || p.port > 65535) {
            cin.clear();
            cout << "Invalid Port! Try again.\n";
        } else break;
    }

    while (true) {
        cout << "Risk Score (1-10): ";
        cin >> p.riskScore;

        if (cin.fail() || p.riskScore < 1 || p.riskScore > 10) {
            cin.clear();
            cout << "Invalid Risk Score! Try again.\n";
        } else break;
    }

    return p;
}

//////////////////////////////////////////////////////
//                 PACKET SYSTEM                    //
//////////////////////////////////////////////////////

class Queue {
private:
    Packet* front;
    Packet* rear;

public:
    Queue() { front = rear = NULL; }

    bool isEmpty() {
        return front == NULL;
    }

    void enqueue(Packet p) {
        Packet* newPacket = new Packet;
        *newPacket = p;
        newPacket->next = NULL;

        if (rear == NULL) {
            front = rear = newPacket;
        } else {
            rear->next = newPacket;
            rear = newPacket;
        }
    }

    Packet dequeue() {
        Packet empty;
        empty.next = NULL;

        if (isEmpty())
            return empty;

        Packet* temp = front;
        Packet p = *temp;

        front = front->next;

        if (front == NULL)
            rear = NULL;

        delete temp;
        return p;
    }
};

//////////////////////////////////////////////////////
//              RULE SYSTEM (CIRCULAR LIST)        //
//////////////////////////////////////////////////////

class RuleNode {
public:
    string rule;
    RuleNode* next;

    RuleNode(string r) {
        rule = r;
        next = NULL;
    }
};

class RuleList {
private:
    RuleNode* head;

public:
    RuleList() {
        head = NULL;
    }

    void addRule(string r) {
        RuleNode* n = new RuleNode(r);

        if (head == NULL) {
            head = n;
            head->next = head;
        } else {
            RuleNode* temp = head;

            while (temp->next != head)
                temp = temp->next;

            temp->next = n;
            n->next = head;
        }

        cout << "Rule Added: " << r << endl;
    }

    string evaluate(Packet p, string &reason) {

        if (head == NULL)
            return "ALLOW";

        string decision = "ALLOW";
        reason = "No matching rule found";

        RuleNode* temp = head;

        do {
            string r = temp->rule;

            if (r == "BLOCK_HIGH_RISK" && p.riskScore > 7) {
                decision = "BLOCK";
                reason = "High risk";
            }

            if (r.find("BLOCK_IP_") == 0) {
                string ip = r.substr(9);
                if (p.sourceIP == ip) {
                    decision = "BLOCK";
                    reason = "IP blocked";
                }
            }

            if (r.find("BLOCK_PROTOCOL_") == 0) {
                string proto = r.substr(15);
                if (p.protocol == proto) {
                    decision = "BLOCK";
                    reason = "Protocol blocked";
                }
            }

            if (r.find("BLOCK_PORT_") == 0) {
                try {
                    int port = stoi(r.substr(11));
                    if (p.port == port) {
                        decision = "BLOCK";
                        reason = "Port blocked";
                    }
                } catch (...) {
				   cout << "Invalid rule format\n";
				}
            }

            // ALLOW RULES: OVER RIDING 
            if (r.find("ALLOW_PORT_") == 0) {
                try {
                    int port = stoi(r.substr(11));
                    if (p.port == port) {
                        decision = "ALLOW";
                        reason = "Port allowed";
                    }
                } catch (...) {
				   cout << "Invalid rule format\n";
				}
            }

            if (r.find("ALLOW_PROTOCOL_") == 0) {
                string proto = r.substr(15);
                if (p.protocol == proto) {
                    decision = "ALLOW";
                    reason = "Protocol allowed";
                }
            }

            temp = temp->next;

        } while (temp != head);

        return decision;
    }
};

//////////////////////////////////////////////////////
//        PROTOCOL SEGMENTATION (ARRAY QUEUES)     //
//////////////////////////////////////////////////////

Queue protocolQueues[4];

void segmentPacket(Packet p) {
    if (p.protocol == "HTTP") protocolQueues[0].enqueue(p);
    else if (p.protocol == "DNS") protocolQueues[1].enqueue(p);
    else if (p.protocol == "FTP") protocolQueues[2].enqueue(p);
    else if (p.protocol == "SSH") protocolQueues[3].enqueue(p);
    else cout << "Unknown protocol !\n";
}

//////////////////////////////////////////////////////
//          PRIORITY QUEUE (THREATS)               //
//////////////////////////////////////////////////////

struct ThreatNode {
    Packet data;
    int priority;
    ThreatNode* next;
};

class PriorityQueue {
private:
    ThreatNode* head;

public:
    PriorityQueue() { head = NULL; }

    void insert(Packet p) {
        ThreatNode* n = new ThreatNode{p, p.riskScore, NULL};

        if (!head || p.riskScore > head->priority) {
            n->next = head;
            head = n;
            return;
        }

        ThreatNode* temp = head;
        while (temp->next && temp->next->priority >= p.riskScore)
            temp = temp->next;

        n->next = temp->next;
        temp->next = n;
    }

    void process() {
    if (!head) {
        cout << "No threats\n";
        return;
    }

    cout << "\n=== Processing Threat Queue ===\n";

    while (head) {
        cout << "Processing Packet ID: " 
             << head->data.id 
             << " | Risk: " << head->priority << endl;

        ThreatNode* temp = head;
        head = head->next;
        delete temp;
    }
}
};

//////////////////////////////////////////////////////
//               TRACE STACK                       //
//////////////////////////////////////////////////////

struct TraceNode {
    Packet data;
    string decision;
    string reason;
    TraceNode* next;
};

class TraceStack {
private:
    TraceNode* top;

public:
    TraceStack() { top = NULL; }

    void push(Packet p, string decision, string reason) {
        TraceNode* n = new TraceNode{p, decision, reason, top};
        top = n;
    }

    void show() {
        TraceNode* temp = top;
        while (temp) {
            cout << "Packet ID: " << temp->data.id << endl;
            cout << "Decision : " << temp->decision << endl;
            cout << "Reason   : " << temp->reason << endl;
            temp = temp->next;
        }
    }
};

//////////////////////////////////////////////////////
//            BLACKLIST (SORTED LIST)              //
//////////////////////////////////////////////////////

struct BlackNode {
    string ip;
    BlackNode* next;
};

class Blacklist {
private:
    BlackNode* head;

public:
    Blacklist() { head = NULL; }

    bool search(string ip) {
        BlackNode* temp = head;
        while (temp) {
            if (temp->ip == ip) return true;
            temp = temp->next;
        }
        return false;
    }

    void insert(string ip) {
        if (search(ip)) return;

        BlackNode* n = new BlackNode{ip, NULL};

        if (!head || ip < head->ip) {
            n->next = head;
            head = n;
            return;
        }

        BlackNode* temp = head;
        while (temp->next && temp->next->ip < ip)
            temp = temp->next;

        n->next = temp->next;
        temp->next = n;
    }
};

//////////////////////////////////////////////////////
//                 STATISTICS                      //
//////////////////////////////////////////////////////

int total = 0, allowed = 0, blocked = 0;

void updateStats(string decision) {
    total++;
    if (decision == "ALLOW") allowed++;
    else blocked++;
}

void processProtocolQueues(Queue protocolQueues[4],
                           RuleList &rules,
                           PriorityQueue &pq,
                           TraceStack &trace,
                           Blacklist &bl) {

    string protocols[4] = {"HTTP", "DNS", "FTP", "SSH"};

    for (int i = 0; i < 4; i++) {

        cout << "\n=== Processing " << protocols[i] << " Queue ===\n";

        while (!protocolQueues[i].isEmpty()) {

            Packet p = protocolQueues[i].dequeue();

            string decision;
            string reason;

            if (bl.search(p.sourceIP)) {
                decision = "BLOCK";
                reason = "IP found in blacklist";
            } else {
                decision = rules.evaluate(p, reason);
            }

            if (p.riskScore >= 8 && p.riskScore <= 9)
            pq.insert(p);

            else if (p.riskScore >= 10) {
            bl.insert(p.sourceIP);
            decision = "BLOCK";
            reason = "Critical threat auto-blacklisted";
}

            updateStats(decision);
            trace.push(p, decision, reason);

            cout << "Final Decision: " << decision << endl;
        }
    }
}

//////////////////////////////////////////////////////
//                     MAIN                        //
//////////////////////////////////////////////////////

int main() {

    Queue mainQueue;
    RuleList rules;
    PriorityQueue pq;
    TraceStack trace;
    Blacklist bl;

    int choice;

    do {
    	cout << "+============== Packet Inspection Firewall Simulator ==============+"<<endl;
        cout << "\n1.Add Packet\n2.Add Rule\n3.Process Packet\n4.Show Trace\n5.Process Threat\n6.Process Protocol Queues\n7.Exit\n";
        cout << "\n+================================================================+";
        cout << "\nEnter choice: \n";
		cin >> choice;
        cin.ignore();

        if (choice == 1) {
            Packet p = createPacket();
            mainQueue.enqueue(p);
        }

        else if (choice == 2) {
            string r;
            cout << "Enter Rule: ";
            getline(cin, r);   
            rules.addRule(r);
        }

        else if (choice == 3) {

            if (mainQueue.isEmpty())
                cout << "Queue Empty\n";

            while (!mainQueue.isEmpty()) {
                Packet p = mainQueue.dequeue();
                segmentPacket(p);
            }

            cout << "Packets segmented successfully.\n";
        }

        else if (choice == 4) trace.show();

        else if (choice == 5) pq.process();

        else if (choice == 6)
            processProtocolQueues(protocolQueues, rules, pq, trace, bl);

    } while (choice != 7);

    return 0;
}