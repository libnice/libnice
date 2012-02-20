..\glib\bin\glib-genmarshal.exe --header --prefix=agent_marshal ..\agent\agent-signals-marshal.list > ..\agent\agent-signals-marshal.h
echo #include "agent-signals-marshal.h" > ..\agent\agent-signals-marshal.c
..\glib\bin\glib-genmarshal.exe --body --prefix=agent_marshal ..\agent\agent-signals-marshal.list >> ..\agent\agent-signals-marshal.c
