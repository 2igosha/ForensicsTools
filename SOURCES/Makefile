all: parse_evtx

SOURCES = main_parse_evtx.cpp wintime.h win_types.h igmacro.h eventlist.h

parse_evtx: ${SOURCES}
	$(CXX) -s -o parse_evtx -O3 -flto main_parse_evtx.cpp

clean:
	rm parse_evtx
