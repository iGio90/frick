# Commands list
|   command   |              short              |                                        info                                         |
|-------------|---------------------------------|-------------------------------------------------------------------------------------|
|  add        |                                 |  add offset from base 0x0 in arg0 with optional name for this target in other args  |
|  attach     |  att                            |  attach to target package name in arg0 with target module name in arg1              |
|  backtrace  |  bt                             |                                                                                     |
|  destruct   |  des,ds                         |  read at address arg0 for len arg1 and optional depth arg2                          |
|  disasm     |  d,dis                          |  disassemble the given hex payload in arg0 or a pointer in arg0 with len in arg1    |
|  find       |  f,fi                           |  utilities to find stuffs                                                           |
|  help       |  h                              |                                                                                     |
|  hexdump    |  hd,hdump                       |  a shortcut to memory read command                                                  |
|  info       |  i,in                           |  get information about your target                                                  |
|  memory     |  m,mem                          |  memory operations                                                                  |
|  pack       |  pa                             |  pack value in arg0 to return a string usable with memory write                     |
|  print      |  p,pr                           |                                                                                     |
|  quit       |  q                              |                                                                                     |
|  registers  |  r,reg,regs                     |  interact with registers                                                            |
|  run        |  c,cont,continue,go,next,start  |  continue the execution of the process to the next target offset                    |
|  session    |  s,ss                           |                                                                                     |
|  set        |                                 |                                                                                     |

---
# find sub commands
|  command  |   short    |                                info                                 |
|-----------|------------|---------------------------------------------------------------------|
|  export   |  e,ex,exp  |  find export name arg0 in target module or in optional module arg1  |

# info sub commands
|  command  |        short         |                         info                         |
|-----------|----------------------|------------------------------------------------------|
|  modules  |  module,mod,mo,md,m  |  list all modules or single module in optional arg0  |
|  ranges   |  range,r,rg          |  list all ranges or single range in optional arg0    |

# memory sub commands
|  command  |      short      |                                     info                                     |
|-----------|-----------------|------------------------------------------------------------------------------|
|  alloc    |  a,al           |  allocate arg0 size in the heap and return the pointer                       |
|  write    |  wr,w           |  write into address arg0 the bytes in args... (de ad be ef)                  |
|  protect  |  prot,pro,pr,p  |  protect address in arg0 for the len arg1 and the prot format in arg2 (rwx)  |
|  read     |  rd,r           |  read bytes from address in arg0 for len in arg1                             |

# registers sub commands
|  command  |  short  |                  info                   |
|-----------|---------|-----------------------------------------|
|  write    |  wr,w   |  write in register arg0 the value arg1  |

# session sub commands
|  command  |  short  |                                           info                                           |
|-----------|---------|------------------------------------------------------------------------------------------|
|  load     |  l,ld   |  load session from previously saved information                                          |
|  save     |  s,sv   |  saves current target offsets, package and module to be immediatly executed with 'load'  |

# set sub commands
|  command   |  short  |           info            |
|------------|---------|---------------------------|
|  capstone  |  cs     |  capstone configurations  |

---
# memory read sub commands
|    command    |            short             |                                          info                                          |
|---------------|------------------------------|----------------------------------------------------------------------------------------|
|  pointer      |  p,ptr                       |  read a pointer from address in arg0                                                   |
|  byte         |  b                           |  read a signed byte from address in arg0 with optional endianness in arg1 (le/be)      |
|  int          |  i                           |  read a signed int from address in arg0 with optional endianness in arg1 (le/be)       |
|  long         |  l                           |  read a signed long from address in arg0 with optional endianness in arg1 (le/be)      |
|  short        |  s                           |  read a signed short from address in arg0 with optional endianness in arg1 (le/be)     |
|  ubyte        |  ub                          |  read an unsigned byte from address in arg0 with optional endianness in arg1 (le/be)   |
|  uint         |  ui                          |  read an unsigned int from address in arg0 with optional endianness in arg1 (le/be)    |
|  ulong        |  ul                          |  read an unsigned long from address in arg0 with optional endianness in arg1 (le/be)   |
|  ushort       |  us                          |  read an unsigned short from address in arg0 with optional endianness in arg1 (le/be)  |
|  ansistring   |  ansistr,ansi,ans            |  read ansi string from address in arg0 and optional len in arg1                        |
|  asciistring  |  asciistr,ascii,acs          |  read ascii string from address in arg0 and optional len in arg1                       |
|  utf16string  |  utf16str,utf16s,utf16,u16s  |  read utf16 string from address in arg0 and optional len in arg1                       |
|  utf8string   |  utf8str,utf8s,utf8,u8s      |  read utf8 string from address in arg0 and optional len in arg1                        |

# set capstone sub commands
|  command  |   short    |              info               |
|-----------|------------|---------------------------------|
|  arch     |  a,ar      |  set the capstone arch in arg0  |
|  mode     |  m,md,mod  |  set the capstone mode in arg0  |

