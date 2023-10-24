//Magic Lantern DryOs Auto re-namingfunction
//@author heder
//@category Auto function remaning script
//@keybinding
//@menupath
//@toolbar

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.reloc.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.*;

// script version 0.1
// This script auto re-names functions by looking after DryOsDebugMsg(),
// The debug string is analyzed.
//
// This is a work in progress ..
// It's messy ...
//

public class demo8 extends GhidraScript {

  public static String name;
  public int funcsfound = 0;
  public int found = 0;

  public void run() throws Exception {
    boolean all = false;

    Function func;

    String oldfuncname;
    String newfuncname;

    String prefix;

    FunctionIterator filter;
    FunctionIterator filternext;

    Address DryOsDebugMsg;
    //DryOsDebugMsg = askAddress("DryOsDebugMsg", "Address of DryOsDebugMsg"); // ask for location of DryOsDebugMsg
    DryOsDebugMsg = toAddr("00000000");

    prefix = askString("Function prefix", "Name or \"*\" (for all) : "); // ask for function prefix
    if (prefix.equals("*")) { //re-name all ?
      all = true;
    }

    println("================================");
    println("Welcome function auto-renamer ... ");
    println("Analysing all functions  ... ");

    DecompInterface decomplib = setUpDecompiler(currentProgram);

    try {
      if (!decomplib.openProgram(currentProgram)) {
        println("Decompile Error: " + decomplib.getLastMessage());
        return;
      }

      // analyse functions
      filter = currentProgram.getFunctionManager().getFunctions(true);
      while (filter.hasNext()) {
        func = filter.next();
        oldfuncname = func.getSignature().getName();

        Address adr1 = func.getEntryPoint();
        long adr2 = adr1.getUnsignedOffset();
        String hexByte = Integer.toHexString((int) adr2);
        //println("function :" + oldfuncname + " : " + hexByte);

        //////////////////////////////////////////////////////
        // ends at functions for quick debugging  ..
        //String brk2 = "fe10f064";
        //if (brk2.equals(hexByte))
        //{
        //  println("ending program");
        //  return;
        //}
        ////////////////////////////////////////////////////

        if (all == true || oldfuncname.contains(prefix)) {
          Address adr = func.getEntryPoint();
          newfuncname = AnalyseCode(oldfuncname, func, DryOsDebugMsg);

          if (newfuncname.equals("")) continue;

          long inst = CountInstruction(func);
          newfuncname = newfuncname + "_" + inst;

          long calls = CountCalls(func);
          newfuncname = newfuncname + "_" + calls;
          found++;
          println(oldfuncname + " >> " + newfuncname + " >> " + found);
          func.setName(newfuncname, SourceType.ANALYSIS);
        }
      }
    } finally {
      decomplib.dispose();
    }
  }

  private DecompInterface setUpDecompiler(Program program) {
    DecompInterface decomplib = new DecompInterface();

    DecompileOptions options;
    options = new DecompileOptions();
    OptionsService service = state.getTool().getService(OptionsService.class);
    if (service != null) {
      ToolOptions opt = service.getOptions("Decompiler");
      options.grabFromToolAndProgram(null, opt, program);
    }
    decomplib.setOptions(options);

    decomplib.toggleCCode(true);
    decomplib.toggleSyntaxTree(true);
    decomplib.setSimplificationStyle("decompile");

    return decomplib;
  }

  /* Analyse the code
   * Search for bl DryOsDebugMsg(x,y,str,...) and retrieve the string
   */
  public String AnalyseCode(String funcname, Function f, Address DebugAdr) {
    String nem;
    String str;
    name = "";

    Address adr = f.getEntryPoint();
    Address stradr;
    Instruction inst = getInstructionAt(adr);
    Object obj;

    while (true) {
      // This is nessasary, Ghidra can create function, but can't decompile them.
      // In this case we get a NullException
      try {
        adr = inst.getAddress();
      } catch (Exception e) {
        return name;
      }

      /* outside function - return */
      if (getFunctionContaining(adr) != f) break;

      nem = inst.getMnemonicString();

      //////////////////////////////////////////////////////
      // break at this instruction .. analyse (fe265c9c)
      // long adr2 = adr.getUnsignedOffset();
      // String hexByte = Integer.toHexString((int)adr2);
      // String brk = "fe255912";
      // if (brk.equals(hexByte))
      // {
      //Object ooo = inst.getOpObjects(0)[0];
      //println("Found instruction : " + nem.toString() + " : " + ooo.toString());
      //  return "";
      // }
      ////////////////////////////////////////////////////

      // Location of DryosDebugMessageFunc
      String dryos1 = "fe651160"; // 7D2
      String dryos2 = "fe65129c"; // 7D2
      String dryos3 = "fecc8aa0"; // 7D2
      String dryos4 = "fe11f394"; // 1300D

      String cur_inst_addr = adr.toString();

      if (nem.equals("bl")) {
        obj = inst.getOpObjects(0)[0];

        if (
          obj.toString().equals(dryos1) ||
          obj.toString().equals(dryos2) ||
          obj.toString().equals(dryos4) ||
          obj.toString().equals(dryos3)
        ) { // DryOsDebugMsg address ?
          // Find string address (ldr r3) doing backwards iterations (max 8)
          // This will fail on some function due to branching
          Instruction itmp = inst;
          for (int j = 0; j < 12; j++) {
            itmp = itmp.getPrevious();
            nem = itmp.getMnemonicString();
            if (
              nem.equals("ldr") || nem.equals("adds") || nem.equals("adr") // 7D2 uses different operands ..
            ) { // now we have two !!!
              obj = itmp.getOpObjects(0)[0];

              if (
                obj.toString().equals("r2") // DryOsDebugMessage(r0,r1,r2 == string,....);
              ) {
                obj = itmp.getOpObjects(1)[0];

                Address instaddr = itmp.getInstructionContext().getAddress();
                if (instaddr == null) return "";

                Address ptradr = toAddr(obj.toString()); // This address contains a pointer to the debug string address
                if (ptradr == null) return "";

                // choose only real addresses, in some cases we get into a wrong spot
                // due to multiple places branching down to a single "bl DryOsDebugMsg" and thus
                // the ldr can be incorrect.
                // if (obj.toString().length() > 3) // skip registers
                {
                  Data msgadrdata = getDataAt(ptradr); // address of debug string
                  if (msgadrdata == null) return ""; // unknown error

                  String msgadrstring = msgadrdata
                    .toString()
                    .replace("addr ", "");

                  Address msgadr = toAddr(msgadrstring); // This address contains a pointer to the debug string address
                  String DebugStr = msgadrdata.toString();
                  String newFunctionName = CreateFunctionName(DebugStr, msgadr);

                  if (!newFunctionName.equals("")) {
                    funcsfound++;
                  }

                  return newFunctionName;
                }
              }
            }
          }
          return name; // only use first DryOsDebugMessage
        }
      }
      inst = inst.getNext();
    }
    return name;
  }

  // Analyse and create the new function name
  // "[%s1] %s2", where
  //
  // 1. First string are incapulated by braces.
  // 2. A white space between the string must be present
  // 3. string s1, must be either a string (a-z,A-Z) or string (a-z,A-Z) +"_ERROR", both inside brackets (_ERROR will be discaded)
  // 4. string s2, must a string (a-z,A-Z), the string is thunkated after first letter.
  // 5. Function will become name = "%s1_%s2"
  // 6. The first string that matches the above is used.
  public String CreateFunctionName(String debugstr, Address x) {
    int start, end;
    boolean escape_normal_name = false;
    String Name = "";

    if (debugstr == null) return "";

    // old method ... really bad ..
    //println(" str1 >> " + debugstr);
    // not all have [????] function name
    //if ((start = debugstr.indexOf("[")) != 0)
    //return Name;
    // skips "ds" .. " ghidra syntax
    start = 4;

    if (debugstr.charAt(4) == '%') return ""; // ds "%??????" useless string, R3 hold data

    //if (escape_normal_name == false)
    //if ((end = debugstr.indexOf("]")) == -1)
    //return Name;

    end = debugstr.length() - 1;
    if (end < start) return "";

    String groupstr = debugstr.substring(start, end);
    groupstr = groupstr.replace("ERROR", "");
    groupstr = groupstr.replace(" ", "");
    groupstr = groupstr.replace("[", "");
    groupstr = groupstr.replace("]", "");
    if (groupstr.length() == 0) return Name;

    //print(" str2 >> " + groupstr);
    //String functionstr = debugstr.substring(end+1,debugstr.length());

    String functionstr = groupstr;

    // old method .. really bad
    //end = functionstr.indexOf("%");
    //if (end == -1)
    //end = functionstr.length();
    //if (end == 0)
    //return Name;
    //functionstr = functionstr.substring(0,end);

    functionstr = functionstr.replace(" ", "_");
    functionstr = functionstr.replaceAll("@", "");
    functionstr = functionstr.replaceAll("$", "");
    functionstr = functionstr.replaceAll("ERROR", "");
    functionstr = functionstr.replaceAll("%s", "_");
    functionstr = functionstr.replaceAll("%d", "_");
    functionstr = functionstr.replaceAll("%x", "_");
    functionstr = functionstr.replaceAll("%lx", "_");
    functionstr = functionstr.replaceAll("#", "");
    functionstr = functionstr.replaceAll("Error", "");
    functionstr = functionstr.replaceAll("error", "");
    functionstr = functionstr.replaceAll("\\[", "");
    functionstr = functionstr.replaceAll("\\]", "_");
    functionstr = functionstr.replaceAll("\\(", "_");
    functionstr = functionstr.replaceAll("\\)", "_");
    functionstr = functionstr.replaceAll("\\*", "_");
    functionstr = functionstr.replaceAll("\\=", "_");
    functionstr = functionstr.replaceAll("__", "_");
    functionstr = functionstr.replaceAll("_ _", "_");
    functionstr = functionstr.replaceAll("  ", "_");
    functionstr = functionstr.replaceAll("\\!", "");
    functionstr = functionstr.replaceAll("\\:", "");
    functionstr = functionstr.replaceAll("\\>", "");
    functionstr = functionstr.replaceAll("\\<", "");
    functionstr = functionstr.replaceAll("\\^", "");
    functionstr = functionstr.replaceAll("\\r", "");
    functionstr = functionstr.replaceAll("\\n", "");
    functionstr = functionstr.replaceAll("\\+", "");
    functionstr = functionstr.replaceAll("\\-", "");
    functionstr = functionstr.replaceAll("__", "_");
    functionstr = functionstr.replaceAll("__", "_");
    functionstr = functionstr.replaceAll("__", "_");

    if (functionstr.length() == 0) return Name;

    if (functionstr.indexOf("\t") != -1) return Name;

    // if last char == "_"
    if (functionstr.charAt(functionstr.length() - 1) == '_') functionstr =
      functionstr.substring(0, functionstr.length() - 1);

    String finalname = "";

    if (functionstr.length() < 1) return finalname;

    // if first char == "_"
    if (functionstr.charAt(0) == '_') finalname =
      functionstr.substring(1, functionstr.length() - 1); else finalname =
      functionstr;

    //String finalname = groupstr + "_" + functionstr;
    finalname = finalname.replace("  ", "_");
    finalname = finalname.replaceAll("__", "_");

    return finalname;
  }

  public String memToString(byte[] bytes) {
    String output = "";
    for (int i = 0; i < bytes.length; i++) {
      if (bytes[i] == 0) break;

      output += (char) bytes[i];
    }
    return output;
  }

  public long CountInstruction(Function f) {
    long inst = 0;
    Address addrStart, addrEnd;

    addrEnd = f.getBody().getMaxAddress();
    addrStart = f.getEntryPoint();

    inst = addrEnd.subtract(addrStart);
    inst = inst >> 2;
    return inst;
  }

  public long CountCalls(Function f) {
    long instCount = 0;
    long calls = 0;
    String nem;

    Address addrStart, addrEnd;
    Instruction inst;

    addrEnd = f.getBody().getMaxAddress();
    addrStart = f.getEntryPoint();
    instCount = addrEnd.subtract(addrStart);
    instCount = instCount >> 2;

    inst = getInstructionAt(addrStart);
    while (instCount > 0) {
      if (inst == null) break;

      nem = inst.getMnemonicString();
      if (nem.equals("bl")) {
        calls++;
      }

      inst = inst.getNext();
      instCount--;
    }
    return calls;
  }
}
