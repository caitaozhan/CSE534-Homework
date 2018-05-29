# CSE532-Code
Fundamentals of computer networks

Homework 1: [All about DNS](https://github.com/caitaozhan/CSE534-Code/blob/master/homework-1/assignment1.pdf). I scored 95/100. I lost 5 points because my dnssec program was not stable. It worked perfectly well when I submitted the homework. But a bug came out of nowhere when the TA was grading homework :(

Homework 2: [HTTP, TCP, and WireShark](https://github.com/caitaozhan/CSE534-Code/blob/master/homework-2/Assignment2.pdf). I scored 91/100. I made a mistake while calculating the lost rate in part A (c). My denominator in the lost rate function was wrong. I counted packets in both directions, but the right way is to only count the packets from sender to receiver. Because the packets from receiver to sender (ACKs) is not important. The wrong lost rate also caused a wrong estimated throughput in part D. Also had a very minor mistake in part C (1), missing a tuple for HTTP GET segment.

Homework 3: [Networking](https://github.com/caitaozhan/CSE534-Homework/blob/master/homework-3/homework3.pdf). I scored 92/100. I didn't went to the office hour of homework 3 (because the time overlap with a final exam), so I don't know what went wrong. 

---

Statistics of the three homeworks:

| | mean | median | me |
| -- | --| --| --|
|hw1 | 79.29 | 87.5| 95 |
|hw2 | 79.32 | 85| 91 |
| hw3 | 79.44 | 86 | 92 |
