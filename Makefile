
FLAGS=-std=c++11 -l pcap -fpermissive -lpthread

defualt:main.cpp
	g++  main.cpp -o badrouter ${FLAGS}
