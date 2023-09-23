from ghidra.program.model.symbol import SourceType
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.app.services import DataTypeManagerService
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.listing import ParameterImpl,VariableStorage
from ghidra.program.model.data import SignedByteDataType,PointerDataType,VoidDataType,BooleanDataType,ByteDataType,ArrayDataType,DataTypeConflictHandler,CategoryPath,EnumDataType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.app.util.cparser.C import CParser

if True:
	mem = currentProgram.getMemory()
	page = mem.getBlock(toAddr(0x0000))
	if not page:
		page = mem.createUninitializedBlock("ZERO_PAGE", toAddr(0x0000), 0x100, 0)
	page.setWrite(True)
	page.setExecute(True)
	page = mem.getBlock(toAddr(0x0100))
	if not page:
		page = mem.createUninitializedBlock("STACK", toAddr(0x0100), 0x100, 0)
	page.setWrite(True)
	page.setExecute(True)
	page = mem.getBlock(toAddr(0x0200))
	if not page:
		page = mem.createUninitializedBlock("PAGE2", toAddr(0x0200), 0x100, 0)
	page.setWrite(True)
	page.setExecute(True)
	page = mem.getBlock(toAddr(0x0300))
	if not page:
		page = mem.createUninitializedBlock("PAGE3", toAddr(0x0300), 0x100, 0)
	page.setWrite(True)
	page.setExecute(True)
	page = mem.getBlock(toAddr(0x0400))
	if not page:
		page = mem.createUninitializedBlock("PAGE4", toAddr(0x0400), 0x100, 0)
	page.setWrite(True)
	page.setExecute(True)
	page = mem.getBlock(toAddr(0x0500))
	if not page:
		page = mem.createUninitializedBlock("PAGE5", toAddr(0x0500), 0x100, 0)
	page.setWrite(True)
	page.setExecute(True)
	page = mem.getBlock(toAddr(0xC000))
	if not page:
		page = mem.createUninitializedBlock("UNMAPPED", toAddr(0xC000), 0x1000, 0)
	page.setWrite(True)
	ioMem = mem.getBlock(toAddr(0xD000))
	if not ioMem:
		ioMem = mem.createUninitializedBlock("IOMEM", toAddr(0xD000), 0x800, 0)
	if ioMem:
		ioMem.setVolatile(True)
		ioMem.setWrite(True)
	romMem = mem.getBlock(toAddr(0xD800))
	if not romMem:
		romMem = mem.createUninitializedBlock("ROM", toAddr(0xD800), 0x2800, 0)
	if romMem:
		romMem.setWrite(False)
		romMem.setExecute(True)

LABELS = {
	0x0000 : ("byte LNFLG", "LINBUG RAM"),
	0x0001 : ("byte NGFLAG", "POWER-UP SELF-TEST FLAG"),
	0x0002 : ("pointer CASINI", "CASSETTE INIT LOC"),
	0x0004 : ("pointer RAMLO", "RAM POINTER MEM TST"),
	0x0006 : ("byte TRAMSZ", "TEMP REG RAM SIZE"),
	0x0007 : ("byte TSTDAT", "RAM TEST DATA REG"),
	0x0008 : ("byte WARMST", "WARM START FLAG"),
	0x0009 : ("byte BOOTQ", "SUCCESSFUL BOOT FLG"),
	0x000A : ("pointer DOSVEC", "DOS START VECTOR"),
	0x000C : ("pointer DOSINI", "DOS INIT ADDRESS"),
	0x000E : ("pointer APPMHI", "APPL MEM HI LIMIT"),
	0x0010 : ("byte POKMSK", "MASK POKEY IRQ"),
	0x0011 : ("byte BRKKEY", "BREAK KEY FLAG"),
	0x0012 : ("byte RTCLOK[3]", "REAL TIME CLOCK"),
	0x0015 : ("pointer BUFADR", "INDIRECT BUFF ADDR"),
	0x0017 : ("byte ICCOMT", "COMMAND FOR VECTOR"),
	0x0018 : ("pointer DSKFMS", "FMS POINTER"),
	0x001A : ("pointer DSKUTL", "DISK UTILITIES PTR"),
	0x001C : ("byte ABUFPT[4]", "RESERVED"),
	0x0020 : ("byte ICHIDZ", "HANDLER INDEX #"),
	0x0021 : ("byte ICDNOZ", "DEVICE NUMBER"),
	0x0022 : ("byte ICCOMZ", "COMMAND CODE"),
	0x0023 : ("byte ICSTAZ", "STATUS RETURN"),
	0x0024 : ("byte ICBALZ", "BUFFER ADDRESS"),
	0x0025 : ("byte ICBAHZ", ""),
	0x0026 : ("byte ICPTLZ", "PUT BYTE ROUTINE-1"),
	0x0027 : ("byte ICPTHZ", ""),
	0x0028 : ("byte ICBLLZ", "BUFFER LENGTH"),
	0x0029 : ("byte ICBLHZ", ""),
	0x002A : ("byte ICAX1Z", "AUXILIARY BYTES"),
	0x002B : ("byte ICAX2Z", ""),
	0x002C : ("byte ICSPRZ[2]", "SPARE BYTES"),
	0x002E : ("byte ICIDNO", "IOCB # X 16"),
	0x002F : ("byte CIOCHR", "CIO CHARACTER BYTE"),
	0x0030 : ("byte STATUS", "INTERNAL STATUS"),
	0x0031 : ("byte CHKSUM", "CHECKSUM"),
	0x0032 : ("byte BUFRLO", "DATA BUFFER LO BYTE"),
	0x0033 : ("byte BUFRHI", "DATA BUFFER HI BYTE"),
	0x0034 : ("byte BFENLO", "NEXT BYTE PAST DATA"),
	0x0035 : ("byte BFENHI", "BUFFER (HI & LO)"),
	0x0036 : ("byte LTEMP", "LOADER TEMP"),
	0x0038 : ("byte BUFRFL", "DATA BUFFR FULL FLG"),
	0x0039 : ("byte RECVDN", "RECIEVE DONE FLAG"),
	0x003A : ("byte XMTDON", "XMIT DONE FLAG"),
	0x003B : ("byte CHKSNT", "CHECKSUM SENT FLAG"),
	0x003C : ("byte NOCKSM", "NO CHKSUM SENT FLAG"),
	0x003D : ("byte BPTR", "CASSETTE DATA INDEX"),
	0x003E : ("byte FTYPE", "INTERRECORD GAP TYPE"),
	0x003F : ("byte FEOF", "END OF FILE FLAG"),
	0x0040 : ("byte FREQ", "BEEP COUNT"),
	0x0041 : ("byte SOUNDR", "NOISY I/O FLAG"),
	0x0042 : ("byte CRITIC", "CRITICAL MODE"),
	0x0043 : ("byte FMSZPG", "FMS ZERO PAGE"),

	0x004A : ("byte ZCHAIN[2]", "HANDLER LOADER TEMP"),
	0x004C : ("byte DSTAT", "DISPLAY STATUS"),
	0x004D : ("byte ATRACT", "ATTRACT FLAG"),
	0x004E : ("byte DRKMSK", "DARK ATTRACT MASK"),
	0x004F : ("byte COLRSH", "COLOR SHIFTER"),
	0x0050 : ("byte TMPCHR", "TEMP STORAGE"),
	0x0051 : ("byte HOLD1", "TEMP STORAGE"),
	0x0052 : ("byte LMARGN", "LEFT MARGIN (1)"),
	0x0053 : ("byte RMARGN", "RIGHT MARGIN (38)"),
	0x0054 : ("byte ROWCRS", "CURSOR COUNTERS"),
	0x0055 : ("byte COLCRS[2]", ""),
	0x0057 : ("byte DINDEX", "DISPLAY MODE #"),
	0x0058 : ("pointer SAVMSC", "SCREEN MEM ADDR"),
	0x005A : ("byte OLDROW", "DRAW START POSIT"),
	0x005B : ("byte OLDCOL[2]", ""),
	0x005D : ("byte OLDCHR", "DATA UNDER CURSOR"),
	0x005E : ("pointer OLDADR", "CURSOR MEM ADDR"),
	0x0060 : ("pointer FKDEF", "FUNC KEY DEFEAT POINTER"),
	0x0062 : ("byte PALNTS", "PAL/NTSC FLAG"),
	0x0063 : ("byte LOGCOL", "COL IN LOGICAL LINE"),
	0x0064 : ("pointer ADRESS", "TEMP STORAGE"),
	0x0066 : ("pointer MLTEMP", "TEMP STORAGE"),
	0x0068 : ("pointer SAVADR", "TEMP STORAGE"),
	0x006A : ("byte RAMTOP", "AVAILABLE RAM PAGES"),
	0x006B : ("byte BUFCNT", "BUFFER COUNT"),
	0x006C : ("pointer BUFSTR", "EDITOR GETCH POINTR"),
	0x006E : ("byte BITMSK", "BIT MASK"),
	0x006F : ("byte SHFAMT", "PIXEL JUSTIFICATION"),
	0x0070 : ("byte ROWAC[2]", "ROW ACCUMULATOR"),
	0x0072 : ("byte COLAC[2]", "COLUMN ACCUMULATOR"),
	0x0074 : ("byte ENDPT[2]", "LINE LENGTH"),
	0x0076 : ("byte DELTAR", "DELTA ROW"),
	0x0077 : ("byte DELTAC[2]", "DELTA COLUMN"),
	0x0079 : ("pointer KEYDEF", "KEY DEFEAT POINTER"),
	0x007B : ("byte SWPFLG", "SPLIT SCN CURS CNTL"),
	0x007C : ("byte HOLDCH", "KB CHAR TEMP HOLD"),
	0x007D : ("byte INSDAT", "TEMP STORAGE"),
	0x007E : ("byte COUNTR[2]", "DRAW ITERATION CNT"),

#	0x0080 : ("pointer LOWMEM", "Pointer to BASIC's low memory"),
#	0x0082 : ("pointer VNTP", "Beginning address of the variable name table"),
#	0x0084 : ("pointer VNTD", "Pointer to the ending address of the variable name table plus one byte"),
#	0x00D4 : ("byte FR0[6]", "Floating point register 0"),
#	0x00DA : ("byte FRE[6]", "Floating point (internal) register E"),
#	0x00E0 : ("byte FR1[6]", "Floating point register 1"),
#	0x00E6 : ("byte FR2[6]", "Floating point register 2"),

	0x0100 : ("byte STACK[256]", "6502 stack space"),

	0x0200 : ("pointer VDSLST", "display list NMI vector"),
	0x0202 : ("pointer VPRCED", "serial I/O proceed line IRQ vector"),
	0x0204 : ("pointer VINTER", "serial I/O interrupt line IRQ vector"),
	0x0206 : ("pointer VBREAK", "BRK instruction IRQ vector"),
	0x0208 : ("pointer VKEYBD", "keyboard IRQ vector"),
	0x020A : ("pointer VSERIN", "serial input ready IRQ vector"),
	0x020C : ("pointer VSEROR", "serial output ready IRQ vector"),
	0x020E : ("pointer VSEROC", "serial output complete IRQ vector"),
	0x0210 : ("pointer VTIMR1", "POKEY timer 1 IRQ vector"),
	0x0212 : ("pointer VTIMR2", "POKEY timer 2 IRQ vector"),
	0x0214 : ("pointer VTIMR4", "POKEY timer 4 IRQ vector"),
	0x0216 : ("pointer VIMIRQ", "immediate IRQ vector"),
	0x0218 : ("pointer CDTMV1", "countdown timer 1 value"),
	0x021A : ("pointer CDTMV2", "countdown timer 2 value"),
	0x021C : ("pointer CDTMV3", "countdown timer 3 value"),
	0x021E : ("pointer CDTMV4", "countdown timer 4 value"),
	0x0220 : ("pointer CDTMV5", "countdown timer 5 value"),
	0x0222 : ("pointer VVBLKI", "immediate VBLANK NMI vector"),
	0x0224 : ("pointer VVBLKD", "deferred VBLANK NMI vector"),
	0x0226 : ("pointer CDTMA1", "countdown timer 1 vector"),
	0x0228 : ("pointer CDTMA2", "countdown timer 2 vector"),

	0x022A : ("byte CDTMF3", "countdown timer 3 flag (0 = expired)"),
	0x022B : ("byte SRTIMR", "software key repeat timer"),
	0x022C : ("byte CDTMF4", "countdown timer 4 flag (0 = expired)"),
	0x022D : ("byte INTEMP", "temporary"),
	0x022E : ("byte CDTMF5", "countdown timer 5 flag (0 = expired)"),
	0x022F : ("byte SDMCTL", "DMACTL shadow"),
	0x0230 : ("byte SDLSTL", "DLISTL shadow"),
	0x0231 : ("byte SDLSTH", "DLISTH shadow"),
	0x0232 : ("byte SSKCTL", "SKCTL shadow"),
	0x0233 : ("byte LCOUNT", "relocating loader record le:"),
	0x0234 : ("byte LPENH", "light pen horizontal value"),
	0x0235 : ("byte LPENV", "light pen vertical value"),
	0x0236 : ("pointer BRKKY", "BREAK key vector"),
	0x0238 : ("pointer VPIRQ", "parallel device IRQ vector"),
	0x023A : ("byte CDEVIC", "command frame device ID"),
	0x023B : ("byte CCOMND", "command frame command"),
	0x023C : ("byte CAUX1", "command auxiliary 1"),
	0x023D : ("byte CAUX2", "command auxiliary 2"),
	0x023E : ("byte TEMP", "temporary"),
	0x023F : ("byte ERRFLG", "I/O error flag (0 = no error)"),

	0x0240 : ("byte DFLAGS", "disk flags from sector 1"),
	0x0241 : ("byte DBSECT", "disk boot sector count"),
	0x0242 : ("pointer BOOTAD", "disk boot memory address"),
	0x0244 : ("byte COLDST", "coldstart flag (0 = complete)"),
	0x0245 : ("byte RECLEN", "relocating loader record le:"),
	0x0246 : ("byte DSKTIM", "disk format timeout"),
	0x0247 : ("byte PDVMSK", "parallel device selection mask"),
	0x0248 : ("byte SHPDVS", "PDVS (parallel device selec:"),
	0x0249 : ("byte PDIMSK", "parallel device IRQ selection mask"),
	0x024A : ("pointer RELADR", "relocating loader relative :"),
	0x024C : ("byte PPTMPA", "parallel device handler tem:"),
	0x024D : ("byte PPTMPX", "parallel device handler tem:"),

	0x026B : ("byte CHSALT", "character set alternate"),
	0x026C : ("byte VSFLAG", "fine vertical scroll count"),
	0x026D : ("byte KEYDIS", "keyboard disable"),
	0x026E : ("byte FINE", "fine scrolling mode"),
	0x026F : ("byte GPRIOR", "PRIOR shadow"),

	0x0270 : ("byte PADDL0", "potentiometer 0"),
	0x0271 : ("byte PADDL1", "potentiometer 1"),
	0x0272 : ("byte PADDL2", "potentiometer 2"),
	0x0273 : ("byte PADDL3", "potentiometer 3"),
	0x0274 : ("byte PADDL4", "potentiometer 4"),
	0x0275 : ("byte PADDL5", "potentiometer 5"),
	0x0276 : ("byte PADDL6", "potentiometer 6"),
	0x0277 : ("byte PADDL7", "potentiometer 7"),

	0x0278 : ("byte STICK0", "joystick 0"),
	0x0279 : ("byte STICK1", "joystick 1"),
	0x027A : ("byte STICK2", "joystick 2"),
	0x027B : ("byte STICK3", "joystick 3"),

	0x027C : ("byte PTRIG0", "paddle trigger 0"),
	0x027D : ("byte PTRIG1", "paddle trigger 1"),
	0x027E : ("byte PTRIG2", "paddle trigger 2"),
	0x027F : ("byte PTRIG3", "paddle trigger 3"),
	0x0280 : ("byte PTRIG4", "paddle trigger 4"),
	0x0281 : ("byte PTRIG5", "paddle trigger 5"),
	0x0282 : ("byte PTRIG6", "paddle trigger 6"),
	0x0283 : ("byte PTRIG7", "paddle trigger 7"),

	0x0284 : ("byte STRIG0", "joystick trigger 0"),
	0x0285 : ("byte STRIG1", "joystick trigger 1"),
	0x0286 : ("byte STRIG2", "joystick trigger 2"),
	0x0287 : ("byte STRIG3", "joystick trigger 3"),

	0x0288 : ("byte HIBYTE", "relocating loader high byte:"),
	0x0289 : ("byte WMODE", "cassette WRITE mode ($80 = writing)"),
	0x028A : ("byte BLIM", "cassette buffer limit"),
	0x028B : ("byte IMASK", "(not used)"),
	0x028C : ("pointer JVECK", "jump vector or temporary"),
	0x028E : ("pointer NEWADR", "relocating address"),
	0x0290 : ("byte TXTROW", "split screen text cursor row"),
	0x0291 : ("byte TXTCOL[2]", "split screen text cursor column"),
	0x0293 : ("byte TINDEX", "split scree text mode"),
	0x0294 : ("byte TXTMSC[2]", "split screen memory scan counter"),
	0x0296 : ("byte TXTOLD[6]", "OLDROW, OLDCOL, OLDCHR, OLDADR for text"),
	0x029C : ("byte CRETRY", "number of command frame ret:"),
	0x029D : ("byte HOLD3", "temporary"),
	0x029E : ("byte SUBTMP", "temporary"),
	0x029F : ("byte HOLD2", "(not used)"),
	0x02A0 : ("byte DMASK", "display (pixel location) mask"),
	0x02A1 : ("byte TMPLBT", "(not used)"),
	0x02A2 : ("byte ESCFLG", "escape flag ($80 = ESC detected)"),
	0x02A3 : ("byte TABMAP[15]", "(120-bit) tab stop bit map"),
	0x02B2 : ("byte LOGMAP[4]", "(32-bit) logical line bit map"),
	0x02B6 : ("byte INVFLG", "inverse video flag ($80 = inverse)"),
	0x02B7 : ("byte FILFLG", "right fill flag (0 = no fill)"),
	0x02B8 : ("byte TMPROW", "temporary row"),
	0x02B9 : ("byte TMPCOL[2]", "temporary column"),
	0x02BB : ("byte SCRFLG", "scroll occurence flag (0 = not occurred)"),
	0x02BC : ("byte HOLD4", "temporary"),
	0x02BD : ("byte DRETRY", "number of device retries"),
	0x02BE : ("byte SHFLOK", "shift/control lock flags"),
	0x02BF : ("byte BOTSCR", "screen bottom (24 = normal, 4 = split)"),

	0x02C0 : ("byte PCOLR0", "player-missle 0 color/luminance"),
	0x02C1 : ("byte PCOLR1", "player-missle 1 color/luminance"),
	0x02C2 : ("byte PCOLR2", "player-missle 2 color/luminance"),
	0x02C3 : ("byte PCOLR3", "player-missle 3 color/luminance"),

	0x02C4 : ("byte COLOR0", "playfield 0 color/luminance"),
	0x02C5 : ("byte COLOR1", "playfield 1 color/luminance"),
	0x02C6 : ("byte COLOR2", "playfield 2 color/luminance"),
	0x02C7 : ("byte COLOR3", "playfield 3 color/luminance"),

	0x02C8 : ("byte COLOR4", "background color/luminance"),

	0x02C9 : ("byte PARMBL[6]", "relocating loader parameter:"),
	0x02C9 : ("pointer RUNADR", "run address"),
	0x02CB : ("pointer HIUSED", "highest non-zero page addre:"),
	0x02CD : ("pointer ZHIUSE", "highest zero page address"),

#	0x02CF : ("OLDPAR", "6-byte relocating loader parameter:"),
	0x02CF : ("pointer GBYTEA", "GET-BYTE routine address"),
	0x02D1 : ("pointer LOADAD", "non-zero page load address"),
	0x02D3 : ("pointer ZLOADA", "zero page load address"),

	0x02D5 : ("byte DSCTLN[2]", "disk sector length"),
	0x02D7 : ("pointer ACMISR", "ACMI interrupt service rout:"),
	0x02D9 : ("byte KRPDEL", "auto-repeat delay"),
	0x02DA : ("byte KEYREP", "auto-repeat rate"),
	0x02DB : ("byte NOCLIK", "key click disable"),
	0x02DC : ("byte HELPFG", "HELP key flag (0 = no HELP)"),
	0x02DD : ("byte DMASAV", "SDMCTL save/restore"),
	0x02DE : ("byte PBPNT", "printer buffer pointer"),
	0x02DF : ("byte PBUFSZ", "printer buffer size"),

	0x02E4 : ("byte RAMSIZ", "high RAM size"),
	0x02E5 : ("pointer MEMTOP", "top of available user memory"),
	0x02E7 : ("pointer MEMLO", "bottom of available user memory"),
	0x02E9 : ("byte HNDLOD", "user load flag (0 = no hand:"),
	0x02EA : ("byte DVSTAT[4]", "device status buffer"),
	0x02EE : ("byte CBAUDL", "low cassette baud rate"),
	0x02EF : ("byte CBAUDH", "high cassette baud rate"),
	0x02F0 : ("byte CRSINH", "cursor inhibit (0 = cursor on)"),
	0x02F1 : ("byte KEYDEL", "key debounce delay timer"),
	0x02F2 : ("byte CH1", "prior keyboard character"),
	0x02F3 : ("byte CHACT", "CHACTL shadow"),
	0x02F4 : ("byte CHBAS", "CHBASE shadow"),

	0x02F5 : ("byte NEWROW", "draw destination row"),
	0x02F6 : ("byte NEWCOL[2]", "draw destination column"),
	0x02F8 : ("byte ROWINC", "draw row increment"),
	0x02F9 : ("byte COLINC", "draw column increment"),

	0x02FA : ("byte CHAR", "internal character"),
	0x02FB : ("byte ATACHR", "ATASCII character or plot point"),
	0x02FC : ("byte CH", "keyboard code (buffer)"),
	0x02FD : ("byte FILDAT", "right fill data"),
	0x02FE : ("byte DSPFLG", "control character display flag (0 = no)"),
	0x02FF : ("byte SSFLAG", "start/stop flag (0 = not stopped)"),

	0x0300 : ("DCB_STRUCT DCB", "device control block"),

	0x030C : ("byte TIMER1[2]", "initial baud rate timer value"),
	0x030E : ("byte JMPERS", "jumper options"),
	0x030F : ("byte CASFLG", "cassette I/O flag (0 = not cassette I/O)"),
	0x0310 : ("byte TIMER2[2]", "final baud rate timer value"),
	0x0312 : ("byte TEMP1", "temporary"),
	0x0313 : ("byte TEMP2", "temporary"),
	0x0314 : ("byte PTIMOT", "printer timeout"),
	0x0315 : ("byte TEMP3", "temporary"),
	0x0316 : ("byte SAVIO", "saved serial data input indicator"),
	0x0317 : ("byte TIMFLG", "timeout flag (0 = timeout)"),
	0x0318 : ("byte STACKP", "SIO saved stack pointer"),
	0x0319 : ("byte TSTAT", "temporary status"),

	0x031A : ("HATABS_STRUCT HATABS[11]", "handler address table"),

	0x033D : ("byte PUPBT1", "power-up validation byte 1"),
	0x033E : ("byte PUPBT2", "power-up validation byte 2"),
	0x033F : ("byte PUPBT3", "power-up validation byte 3"),

	0x0340 : ("IOCB_STRUCT IOCB[8]", "I/O control blocks"),

	0x03C0 : ("byte PRNBUF[40]", "printer buffer"),
	0x03E8 : ("byte SUPERF", "editor super function flag :"),
	0x03E9 : ("byte CKEY", "cassette boot request flag :"),
	0x03EA : ("byte CASSBT", "cassette boot flag (0 = not:"),
	0x03EB : ("byte CARTCK", "cartridge equivalence checksum"),
	0x03EC : ("byte DERRF", "screen OPEN error flag (0 = not)"),

	0x03ED : ("byte ACMVAR[11]", "11 bytes reserved for ACMI"),
	0x03F8 : ("byte BASICF", "BASIC switch flag (0 = BASIC enabled)"),
	0x03F9 : ("byte MINTLK", "ACMI module interlock"),
	0x03FA : ("byte GINTLK", "cartridge interlock"),
	0x03FB : ("pointer CHLINK", "loaded handler chain link"),
	0x03FD : ("byte CASBUF[3]", "first 3 bytes of cassette buffer"),

    0xC000 : ("byte UNKNOWN_C000[4096]", "Typically unmapped, but can be RAM or ROM"),

    0xD000 : ("CTIA_STRUCT CTIA", "CTIA"),
    0xD200 : ("POKEY_STRUCT POKEY", "POKEY"),
    0xD300 : ("PIA_STRUCT PIA", "PIA"),
    0xD400 : ("ANTIC_STRUCT ANTIC", "ANTIC"),

	0xD800 : ("void AFP(void)", "ATASCII to floating point"),
	0xD8E6 : ("void FASC(void)", "Floating point to ATASCII"),
	0xD9AA : ("void IFP(void)", "Integer to floating point"),
	0xD9D2 : ("void FPI(void)", "Floating point to Integer"),
	0xDA44 : ("void ZFR0(void)", "Set to zero"),
	0xDA46 : ("void AF1(void)", "Set register in X to zero"),
	0xDA60 : ("void FSUB(void)", "FR0-FR1 Subtraction"),
	0xDA66 : ("void FADD(void)", "FR0+FR1 Addition"),
	0xDADB : ("void FMUL(void)", "FR0*FR1 Multiplication"),
	0xDB28 : ("void FDIV(void)", "FR0/FR1 Division"),
	0xDD40 : ("void PLYEVL(void)", "Polynomial evaluation"),
	0xDD89 : ("void FLDOR(void)", "Floating Load using X,Y"),
	0xDD8D : ("void FLDOP(void)", "Floading Load using FLPTR"),
	0xDD98 : ("void FLD1R(void)", "Floating Load using X,Y"),
	0xDD9C : ("void FLD1P(void)", "Floating Load using FLPTR"),
	0xDDA7 : ("void FSTOR(void)", "Floating store using X,Y"),
	0xDDA8 : ("void FSTOP(void)", "Floating store with FLPTR"),
	0xDDB6 : ("void FMOVE(void)", "Move FR0"),
	0xDDC0 : ("void EXP(void)", "Exponentiation - e**FR0"),
	0xDDCC : ("void EXP10(void)", "Exponentiation - 10**FR0"),
	0xDDCD : ("void LOG(void)", "Natural logarithm"),
	0xDED1 : ("void LOG10(void)", "Base 10 logarithm"),

    0xE000 : ("byte ROM_E000[1024]", ""),

    0xE400 : ("HANDLER_TABLE EDITRV", "EDITOR"),
    0xE410 : ("HANDLER_TABLE SCRENV", "TELEVISION SCREEN"),
    0xE420 : ("HANDLER_TABLE KEYBDV", "KEYBOARD"),
    0xE430 : ("HANDLER_TABLE PRINTV", "PRINTER"),
    0xE440 : ("HANDLER_TABLE CASETV", "CASSETTE"),

    0xE450 : ("void DISKIV(void)", "DISK INITIALIZATION"),
    0xE453 : ("bool DSKINV(void)", "DISK INTERFACE"),
    0xE456 : ("void CIOV(void)", "CIO ROUTINE"),
    0xE459 : ("void SIOV(void)", "SIO ROUTINE"),
    0xE45C : ("void SETVBV(byte a, pointer xy)", "SET VERTICAL BLANK VECTORS"),
    0xE45F : ("void SYSVBV(void)", "SYSTEM VERTICAL BLANK ROUTINE"),
    0xE462 : ("void XITVBV(void)", "EXIT VERTICAL BLANK ROUTINE"),
    0xE465 : ("void SIOINV(void)", "SIO INIT"),
    0xE468 : ("void SENDEV(void)", "SEND ENABLE ROUTINE"),
    0xE46B : ("void INTINV(void)", "INTERRUPT HANDLER INIT"),
    0xE46E : ("void CIOINV(void)", "CIO INIT"),
    0xE471 : ("void BLKBDV(void)", "BLACKBOARD MODE"),
    0xE474 : ("void WARMSV(void)", "WARM START ENTRY POINT"),
    0xE477 : ("void COLDSV(void)", "COLD START ENTRY POINT"),
    0xE47D : ("void RBLOKV(void)", "CASSETTE READ BLOCK VECTOR"),
    0xE480 : ("void DSOPIV(void)", "CASSETTE OPEN FOR INPUT VECTOR"),

    0xE483 : ("byte ROM_E483[7019]", ""),
    
    0xFFEE : ("byte REVISION_DATE[3]", "Revision date in BCD: DDMMYY"),
    0xFFF1 : ("byte OPTION_BYTE", "1200XL=1, 600/800XL=2"),
    0xFFF2 : ("byte PART_NUMBER[5]", "Part number in the form AANNNNNN"),
    0xFFF7 : ("byte REVISION_NUMBER", ""),
    0xFFF8 : ("byte CHECKSUM[2]", "Checksum, bytes (LSB/MSB)"),
    0xFFFA : ("pointer NMI_VECTOR", "6502 NMI vector"),
    0xFFFC : ("pointer RESET_VECTOR", "6502 RESET vector"),
    0xFFFE : ("pointer IRQ_VECTOR", "6502 IRQ vector"),
}

STRUCTS = (
"""struct HANDLER_TABLE {
	void *DEVICE_OPEN;
	void *DEVICE_CLOSE;
	void *DEVICE_READ;
	void *DEVICE_WRITE;
	void *DEVICE_STATUS;
	void *DEVICE_SPECIAL;
	byte DEVICE_INITIALIZATION[3];
	byte FILLER;
};""",
"""
struct CTIA_STRUCT {
	byte HPOSP0;
	byte HPOSP1;
	byte HPOSP2;
	byte HPOSP3;
	byte HPOSM0;
	byte HPOSM1;
	byte HPOSM2;
	byte HPOSM3;
	byte SIZEP0;
	byte SIZEP1;
	byte SIZEP2;
	byte SIZEP3;
	byte SIZEM;
	byte GRAFP0;
	byte GRAFP1;
	byte GRAFP2;
	byte GRAFP3;
	byte GRAFM;
	byte COLPM0;
	byte COLPM1;
	byte COLPM2;
	byte COLPM3;
	byte COLPF0;
	byte COLPF1;
	byte COLPF2;
	byte COLPF3;
	byte COLBK;
	byte PRIOR;
	byte VDELAY;
	byte GRACTL;
	byte HITCLR;
	byte CONSOL;
};""",
"""struct POKEY_STRUCT {
	byte AUDF1;
	byte AUDC1;
	byte AUDF2;
	byte AUDC2;
	byte AUDF3;
	byte AUDC3;
	byte AUDF4;
	byte AUDC4;
	byte AUDCTL;
	byte STIMER;
	byte RANDOM;
	byte POTGO;
	byte UNUSED_12;
	byte SEROUT;
	byte IRQEN;
	byte SKCTL;
};""",
"""struct ANTIC_STRUCT {
	byte DMACTL;
	byte CHACTL;
	byte DLISTL;
	byte DLISTH;
	byte NSCROL;
	byte VSCROL;
	byte UNUSED_6;
	byte PMBASE;
	byte UNUSED_8;
	byte CHBASE;
	byte WSYNC;
	byte VCOUNT;
	byte PENH;
	byte PENV;
	byte NMIEN;
	byte NMIRES;
};""",
"""struct PIA_STRUCT {
	byte PORTA;
	byte PORTB;
	byte PACTL;
	byte PBCTL;
};""",
"""struct DCB_STRUCT {
	byte DDEVIC;
	byte DUNIT;
	DCB_COMMAND DCOMND;
	byte DSTATS;
	byte DBUFLO;
	byte DBUFHI;
	byte DTIMLO;
	byte DUNUSE;
	byte DBYTLO;
	byte DBYTHI;
	byte DAUX1;
	byte DAUX2;
};""",
"""struct IOCB_STRUCT {
	byte ICHID;
	byte ICDNO;
	byte ICCOM;
	byte ICSTA;
	byte ICBAL;
	byte ICBAH;
	byte ICPTL;
	byte ICPTH;
	byte ICBLL;
	byte ICBLH;
	byte ICAX1;
	byte ICAX2;
	byte ICSPR[4];
};""",
"""struct HATABS_STRUCT {
	byte DEVICE_NAME;
	pointer HANDLER_ADDR;
};""",
)

ENUMS = {
	"DCB_COMMAND": {
		0x31:'DISKID',
		0x50:'PUTSEC',
		0x52:'READ',
		0x57:'WRITE',
		0x53:'STATC',
		0x21:'FORMAT',
	}
}

data_type_manager = currentProgram.getDataTypeManager()

for enum_dict in ENUMS:
	enum_entries = ENUMS[enum_dict]
	enum = EnumDataType(enum_dict, 1)
	for value in enum_entries:
		enum.add(enum_entries[value], value)
	data_type_manager.addDataType(enum, DataTypeConflictHandler.REPLACE_HANDLER)

for struct_txt in STRUCTS:
	datatype = CParser(data_type_manager).parse(struct_txt)
	datatype.setExplicitPackingValue(1)
	data_type_manager.addDataType(datatype, DataTypeConflictHandler.REPLACE_HANDLER)

for addr in LABELS:
	addr_lookup = LABELS[addr]
	addr = toAddr(addr)
	label = addr_lookup[0]
	comment = addr_lookup[1]
	if label.endswith(')'):
		parser = FunctionSignatureParser(currentProgram.dataTypeManager, state.tool.getService(DataTypeManagerService))
		sig = parser.parse(None, label)
		func = createFunction(addr, None)
		if not func:
			func = getFunctionAt(addr)
		cmd = ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED)
		cmd.applyTo(currentProgram, monitor)
		if addr == toAddr(0xE453): # the return value is a bool in the negative flag
			func.setCustomVariableStorage(True)
			func.setReturn(BooleanDataType(), VariableStorage(currentProgram, currentProgram.getRegister("N")), SourceType.USER_DEFINED)
		elif addr == toAddr(0xE45C): # the parameters are in the A-reg and a 16-bit function address in xy
			func.replaceParameters(FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED,
				ParameterImpl("a", SignedByteDataType(), currentProgram.getRegister("A"), func.getProgram()),
				ParameterImpl("xy", PointerDataType(), VariableStorage(currentProgram, currentProgram.getRegister("X"), currentProgram.getRegister("Y")), func.getProgram())
				)
			func.setReturnType(VoidDataType(), SourceType.USER_DEFINED)
	else:
		dtype,label = label.split(' ')
		arraySize = 1
		if label.endswith(']'):
			label,s = label[:-1].split('[')
			arraySize = int(s)
		new_symbol = currentProgram.getSymbolTable().createLabel(addr, label, currentProgram.getGlobalNamespace(), SourceType.USER_DEFINED)
		new_symbol.setPrimary()
		removeDataAt(addr)
		dataType = data_type_manager.getDataType(CategoryPath.ROOT, dtype)
		if arraySize == 1:
			for displ in range(0,dataType.getLength()):
				removeDataAt(addr.add(displ))
			createData(addr, dataType)
		else:
			for displ in range(0,dataType.getLength() * arraySize):
				removeDataAt(addr.add(displ))
			createData(addr, ArrayDataType(dataType,arraySize, dataType.getLength()))
	setRepeatableComment(addr, "%s" % (comment))

# unused IO space
createData(toAddr(0xd020), ArrayDataType(ByteDataType(), 512-32, 1))
createData(toAddr(0xd210), ArrayDataType(ByteDataType(), 256-16, 1))
createData(toAddr(0xd304), ArrayDataType(ByteDataType(), 256-4, 1))
createData(toAddr(0xd410), ArrayDataType(ByteDataType(), 1024-16, 1))
# FPU
#createData(toAddr(0xd800), ArrayDataType(ByteDataType(), 0x800, 1))
