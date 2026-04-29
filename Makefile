# Makefile for Linux/OpenWrt direct build
CC      ?= gcc
CXX     ?= g++
CXXFLAGS ?= -Wall -O2
LDFLAGS  ?=
LIBS     := $(LDFLAGS) -lpcap

SRCS     = pppoe.cpp common.cpp
OBJS     = $(SRCS:.cpp=.o)
TARGET   = PPPOE

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp common.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
