## Tools for working with RACF Passtickets

This repo contains tools for parseing, unmasking, and generating RACF passtickets.

For more info on RACF Passtickets see:
https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/com.ibm.zos.v2r3.icha700/pass.htm

The passticket generator algorithm
https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.1.0/com.ibm.zos.v2r1.icha300/skalgo.htm#skalgo

- gen_passticket.py			- Generate a passticket
- unmask_passticket.py		- Retrieve secret key from masked RACF entry
- parse_db_ptkt.py          - Parse racf DB to dump passtickets

### Todo
- [x] Add RACF db parser to dump passtickets
- [ ] Refactor generator
- [ ] Refactor parser
