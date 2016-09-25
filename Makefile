
FLAGS=-std=c++11 -l pcap -fpermissive

defualt:main.cpp
	g++  main.cpp -o badrouter ${FLAGS}
