# CSE534-Code
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

My rating on the professor: [11/20/2018](https://www.ratemyprofessors.com/ShowRatings.jsp?tid=2113729)

---

Update: 9/18/2020

In the past two years, my CSE 534 homework repository is getting pretty popular. Below are some traffic statistics. There are 14 unique cloners in the past 14 days. Considering a class of only 30+ students in Fall 2020, this is almost 50% of students cloning! Hope this repository is helping you out the homework. BUT don't get caught in **plagiarism**. Don't do control+C and control+V.

![cse534](https://github.com/caitaozhan/CSE534-Homework/blob/master/CSE534.png)

Fig. 1 clones.

![cse534-2](https://github.com/caitaozhan/CSE534-Homework/blob/master/CSE534-2.png)

Fig. 2 views.
