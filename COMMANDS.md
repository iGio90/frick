# commands list
|   command   |              short              |                                                           info                                                           |
|-------------|---------------------------------|--------------------------------------------------------------------------------------------------------------------------|
|  add        |                                 |  add offset from base 0x0 in arg0 with optional name for this target in other args                                       |
|  attach     |  att                            |  attach to target package name in arg0 with target module name in arg1                                                   |
|  backtrace  |  bt                             |                                                                                                                          |
|  destruct   |  des,ds                         |  read at address arg0 for len arg1 and optional depth arg2                                                               |
|  disasm     |  d,dis                          |  disassemble the given hex payload in arg0 or a pointer in arg0 with len in arg1                                         |
|  emulator   |  e,emu                          |  unicorn emulator                                                                                                        |
|  find       |  fi                             |  utilities to find stuffs                                                                                                |
|  functions  |  fn,fu,fun,func,funct,function  |  list native functions                                                                                                   |
|  help       |  h                              |                                                                                                                          |
|  hexdump    |  hd,hdump                       |  hexdump memory regions pointed by value in args for len in the last arg                                                 |
|  info       |  i,in                           |  get information about your target                                                                                       |
|  inject     |  inj                            |  wrapper of dlopen to inject a binary from a local path in arg0 and custom name in arg1                                  |
|  memory     |  m,mem                          |  memory operations                                                                                                       |
|  once       |  o,on                           |  add a callback for ptr target hit in arg0. the keyword 'init' can be used to do stuffs once module base is retrieved.   |
|  pack       |  pa                             |  pack value in arg0 to return a string usable with memory write                                                          |
|  print      |  p,pr                           |                                                                                                                          |
|  quit       |  ex,exit,q                      |                                                                                                                          |
|  registers  |  r,reg,regs                     |  interact with registers                                                                                                 |
|  remove     |  del,delete,rem                 |  remove an offsets from targets list                                                                                     |
|  run        |  c,cont,continue,go,next,start  |  continue the execution of the process to the next target offset                                                         |
|  scripts    |  sc,scr,script                  |  manage custom frida scripts                                                                                             |
|  session    |  s,ss                           |                                                                                                                          |
|  set        |                                 |                                                                                                                          |

---
# add sub commands
|  command  |   short    |                                       info                                        |
|-----------|------------|-----------------------------------------------------------------------------------|
|  dtinit   |  dti,init  |  mark this target as dt_init function. on android we leak the base before dlopen  |
|  pointer  |  p,ptr     |  add a virtual address in arg0 with optional name in other args                   |

# emulator sub commands
|     command      |  short   |                   info                    |
|------------------|----------|-------------------------------------------|
|  implementation  |  i,impl  |  set a custom unicorn script in arg0      |
|  start           |  s       |  start emulation with exit point in arg0  |

# find sub commands
|  command  |   short    |                                info                                 |
|-----------|------------|---------------------------------------------------------------------|
|  export   |  e,ex,exp  |  find export name arg0 in target module or in optional module arg1  |

# functions sub commands
|  command  |  short  |                                              info                                              |
|-----------|---------|------------------------------------------------------------------------------------------------|
|  add      |  a      |  add a native function with pointer in arg0, return type in arg1 followed by args type if any  |
|  run      |  r      |  run native function pointed by arg0 followed by function args                                 |

# info sub commands
|  command  |        short         |                             info                             |
|-----------|----------------------|--------------------------------------------------------------|
|  modules  |  m,md,mo,mod,module  |  list all modules or single module in optional arg0          |
|  ranges   |  r,range,rg          |  list all ranges or single range in optional arg0            |
|  threads  |  t,th,thread         |  list all threads or single thread with optional tid in rg0  |

# memory sub commands
|  command  |      short      |                                     info                                     |
|-----------|-----------------|------------------------------------------------------------------------------|
|  alloc    |  a,al           |  allocate arg0 size in the heap and return the pointer                       |
|  dump     |  d              |  read bytes in arg0 for len in arg1 and store into filename arg2             |
|  protect  |  p,pr,pro,prot  |  protect address in arg0 for the len arg1 and the prot format in arg2 (rwx)  |
|  read     |  r,rd           |  read bytes from address in arg0 for len in arg1                             |
|  write    |  w,wr           |  write into address arg0 the bytes in args... (de ad be ef)                  |

---
# memory read sub commands
|    command    |            short             |                                          info                                          |
|---------------|------------------------------|----------------------------------------------------------------------------------------|
|  ansistring   |  ans,ansi,ansistr            |  read ansi string from address in arg0 and optional len in arg1                        |
|  asciistring  |  acs,ascii,asciistr          |  read ascii string from address in arg0 and optional len in arg1                       |
|  byte         |  b                           |  read a signed byte from address in arg0 with optional endianness in arg1 (le/be)      |
|  int          |  i                           |  read a signed int from address in arg0 with optional endianness in arg1 (le/be)       |
|  long         |  l                           |  read a signed long from address in arg0 with optional endianness in arg1 (le/be)      |
|  pointer      |  p,ptr                       |  read a pointer from address in arg0                                                   |
|  short        |  s                           |  read a signed short from address in arg0 with optional endianness in arg1 (le/be)     |
|  ubyte        |  ub                          |  read an unsigned byte from address in arg0 with optional endianness in arg1 (le/be)   |
|  uint         |  ui                          |  read an unsigned int from address in arg0 with optional endianness in arg1 (le/be)    |
|  ulong        |  ul                          |  read an unsigned long from address in arg0 with optional endianness in arg1 (le/be)   |
|  ushort       |  us                          |  read an unsigned short from address in arg0 with optional endianness in arg1 (le/be)  |
|  utf16string  |  u16s,utf16,utf16s,utf16str  |  read utf16 string from address in arg0 and optional len in arg1                       |
|  utf8string   |  u8s,utf8,utf8s,utf8str      |  read utf8 string from address in arg0 and optional len in arg1                        |

# registers sub commands
|  command  |  short  |                  info                   |
|-----------|---------|-----------------------------------------|
|  write    |  w,wr   |  write in register arg0 the value arg1  |

# scripts sub commands
|  command  |  short  |                                      info                                      |
|-----------|---------|--------------------------------------------------------------------------------|
|  load     |  l      |  load the frida script with path in arg0                                       |
|  open     |  o,op   |  create or open a new frida script with name in arg0 and start default editor  |
|  unload   |  u,ul   |  unload the frida script with path in arg0                                     |

# session sub commands
|  command  |  short  |                                           info                                           |
|-----------|---------|------------------------------------------------------------------------------------------|
|  load     |  l,ld   |  load session from previously saved information                                          |
|  open     |  o,op   |  edit session file with text editor                                                      |
|  save     |  s,sv   |  saves current target offsets, package and module to be immediatly executed with 'load'  |

# set sub commands
|  command   |  short  |           info            |
|------------|---------|---------------------------|
|  capstone  |  c,cs   |  capstone configurations  |
|  unicorn   |  u,uc   |  unicorn configurations   |

---
# set capstone sub commands
|  command  |   short    |              info               |
|-----------|------------|---------------------------------|
|  arch     |  a,ar      |  set the capstone arch in arg0  |
|  mode     |  m,md,mod  |  set the capstone mode in arg0  |

# set unicorn sub commands
|  command  |   short    |              info              |
|-----------|------------|--------------------------------|
|  arch     |  a,ar      |  set the unicorn arch in arg0  |
|  mode     |  m,md,mod  |  set the unicorn mode in arg0  |

