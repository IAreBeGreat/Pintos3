1) Navagate to pintos/src/tests/threads/
2) Open the file alarm-wait.c
3) Directly under the 31 line add the following
	void
	test_alarm_mega (void)
	{
	  test_sleep (5, 70);
	}

4) In tests.c and add the line '{"alarm-mega", test_alarm_mega}', without the single quotes, just above the 	line containing "alarm-many"
5) In tests.h add the line extern test_func test_alarm_mega; between lines 9 and 10
6) Then open Make.tests and on the 5 line add 'alarm-mega', without the single quotes, between alarm-many and alarm-multiple
7) Finally open Rubric.alarm and on line 7 add '4	alarm-mega', without the single quotes. 
	*Note: The space between 4 and alarm-mega in the instrucion above is a single Tab


