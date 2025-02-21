############################################################################################
##
## Opcode Explainer (Web with Local Cache)
##
## Updated for IDA 7.xx / IDA 9 and Python 3
##
## This plugin fetches an explanation for the opcode under the cursor from 
## Felix Cloutier’s x86 reference at: https://www.felixcloutier.com/x86/
## For the top 50 common opcodes, a local description (with two detailed sentences)
## is used to avoid web traffic. The second sentence details if and how flags are modified.
##
## To install:
##      Copy this script into your IDA plugins directory, e.g.,
##      C:\Program Files\<ida version>\plugins
##
## To use:
##      In the disassembly view, right-click on an instruction and select 
##      "Explain Opcode" to display a description.
##
############################################################################################

__AUTHOR__    = 'Chris Hernandez'
PLUGIN_NAME   = "Opcode Explainer (Web with Local Cache)"
PLUGIN_HOTKEY = "Ctrl+E"  # Optional hotkey
VERSION       = "1.0.0"

import sys
import idc
import idaapi
import idautils
import urllib.request
import re

# Global cache to avoid repeated network requests for the same opcode.
opcode_cache = {}

# Local dictionary for the top 50 common x86/x64 opcodes.
# Each entry consists of two sentences: the first explains the opcode operation,
# and the second explains if (and how) the instruction modifies processor flags.
local_opcode_descriptions = {
    "mov":  "The MOV instruction transfers data from one location to another. It does not modify any processor flags.",
    "add":  "The ADD instruction performs arithmetic addition between two operands, updating the destination with the sum. It modifies the Zero, Sign, Carry, and Overflow flags based on the result.",
    "sub":  "The SUB instruction subtracts the second operand from the first and stores the result. It updates the Zero, Sign, Carry, and Overflow flags accordingly.",
    "jmp":  "The JMP instruction causes an unconditional jump to a specified address. It does not affect the arithmetic flags.",
    "cmp":  "The CMP instruction compares two operands by subtracting one from the other without storing the result. It solely updates the processor flags to reflect the outcome of the comparison.",
    "call": "The CALL instruction transfers control to a subroutine while saving the return address on the stack. It does not generally alter the arithmetic flags.",
    "ret":  "The RET instruction returns control from a subroutine by popping the return address from the stack. It does not modify the processor flags.",
    "push": "The PUSH instruction places a value onto the stack and decrements the stack pointer. It does not change any processor flags.",
    "pop":  "The POP instruction removes a value from the stack and stores it in a register or memory location. It does not affect the processor flags.",
    "lea":  "The LEA (Load Effective Address) instruction calculates the address of its operand and loads it into a register. It does not modify any flags since it only performs address computation.",
    "xor":  "The XOR instruction performs a bitwise exclusive OR between two operands, commonly used to clear a register. It updates the Zero, Sign, Carry, and Overflow flags based on the result.",
    "and":  "The AND instruction performs a bitwise AND between two operands, often used for masking bits. It updates the Zero, Sign, and Parity flags while clearing the Carry and Overflow flags.",
    "or":   "The OR instruction performs a bitwise OR between two operands, combining their bits. It clears the Carry and Overflow flags and updates the Zero, Sign, and Parity flags accordingly.",
    "inc":  "The INC instruction increments the value of an operand by one. It modifies the Zero, Sign, and Overflow flags but leaves the Carry flag unaffected.",
    "dec":  "The DEC instruction decrements the value of an operand by one. It updates the Zero, Sign, and Overflow flags without altering the Carry flag.",
    "nop":  "The NOP instruction performs no operation and is used for timing or alignment. It does not modify any processor flags.",
    "test": "The TEST instruction performs a bitwise AND between two operands without storing the result. It updates the Zero, Sign, Parity, and Auxiliary Carry flags based on the result.",
    "mul":  "The MUL instruction performs an unsigned multiplication of the accumulator by another operand. It may set the Carry and Overflow flags if the upper half of the result is nonzero, while other flags remain undefined.",
    "div":  "The DIV instruction performs an unsigned division of the accumulator by an operand, producing a quotient and remainder. It does not have well-defined effects on the standard arithmetic flags.",
    "imul": "The IMUL instruction performs a signed multiplication of its operands, taking their sign into account. It updates the Carry and Overflow flags similarly to MUL, depending on the result.",
    "idiv": "The IDIV instruction performs signed division of the accumulator by a given operand, yielding a quotient and remainder. It does not reliably modify the standard arithmetic flags.",
    "shl":  "The SHL (Shift Left) instruction shifts the bits of an operand to the left by a specified count, effectively multiplying the operand. It updates the Carry flag and may modify the Zero and Sign flags based on the shifted result.",
    "shr":  "The SHR (Shift Right) instruction shifts the bits of an operand to the right logically, inserting zeros on the left. It modifies the Carry flag and updates the Zero and Sign flags according to the result.",
    "sar":  "The SAR (Shift Arithmetic Right) instruction shifts an operand to the right while preserving its sign bit, performing an arithmetic division. It updates the Carry flag and modifies the Zero and Sign flags based on the outcome.",
    "rol":  "The ROL (Rotate Left) instruction rotates the bits of an operand to the left, with the high-order bit wrapping around to the low-order position. It updates the Carry flag based on the bit that is rotated out.",
    "ror":  "The ROR (Rotate Right) instruction rotates the bits of an operand to the right, with the low-order bit wrapping around to the high-order position. It modifies the Carry flag based on the bit that is rotated out.",
    "clc":  "The CLC instruction clears the Carry flag in the processor's status register. It directly sets the Carry flag to 0.",
    "stc":  "The STC instruction sets the Carry flag in the processor's status register. It directly sets the Carry flag to 1.",
    "cmc":  "The CMC instruction complements (toggles) the state of the Carry flag. It inverts the current state of the Carry flag.",
    "not":  "The NOT instruction performs a bitwise complement of the operand, inverting all its bits. It does not affect any of the processor's status flags.",
    "movsx": "The MOVSX instruction copies a value from a source operand to a destination register while sign-extending it. It does not alter the processor's flag register.",
    "movzx": "The MOVZX instruction transfers data from a source operand to a destination register with zero-extension. It leaves the processor flags unchanged.",
    "je":   "The JE (Jump if Equal) instruction transfers control if the zero flag is set, typically after a comparison. It does not modify any processor flags.",
    "jne":  "The JNE (Jump if Not Equal) instruction causes a jump if the zero flag is clear. It does not affect processor flags.",
    "jg":   "The JG (Jump if Greater) instruction transfers control if a signed comparison indicates the first operand is greater than the second. It does not modify flags.",
    "jge":  "The JGE (Jump if Greater or Equal) instruction causes a jump when the sign flag equals the overflow flag. It does not alter the processor flags.",
    "jl":   "The JL (Jump if Less) instruction transfers control if the first operand is less than the second in a signed comparison. It does not change the processor flags.",
    "jle":  "The JLE (Jump if Less or Equal) instruction jumps if the zero flag is set or the sign flag does not equal the overflow flag. It does not modify the flag register.",
    "ja":   "The JA (Jump if Above) instruction performs an unconditional jump if an unsigned comparison shows the first operand is greater than the second (carry flag clear and zero flag clear). It leaves the flags unchanged.",
    "jae":  "The JAE (Jump if Above or Equal) instruction jumps if the carry flag is clear, used for unsigned comparisons. It does not modify any processor flags.",
    "jb":   "The JB (Jump if Below) instruction transfers control if the carry flag is set, indicating an unsigned lower comparison. It does not alter the processor flags.",
    "jbe":  "The JBE (Jump if Below or Equal) instruction causes a jump if the carry flag is set or the zero flag is set. It does not change the processor flags.",
    "loop": "The LOOP instruction decrements the count in the ECX/RCX register and jumps if the result is nonzero. It does not affect the arithmetic flags aside from updating the counter.",
    "loope": "The LOOPE (Loop if Equal) instruction decrements the counter and jumps if the zero flag is set and the counter is nonzero. It does not modify processor flags beyond the counter decrement.",
    "loopne": "The LOOPNE (Loop if Not Equal) instruction decrements the counter and jumps if the zero flag is clear and the counter is nonzero. It does not alter the processor's flag register aside from updating the counter.",
    "pushf": "The PUSHF instruction pushes the current flags register onto the stack. It does not modify any flags as it only copies their state.",
    "popf": "The POPF instruction pops a value from the stack into the flags register, restoring flag settings. It updates the processor's flags with the popped value.",
    "iret": "The IRET instruction returns from an interrupt by popping the instruction pointer, code segment, and flags from the stack. It restores the processor flags along with other state values.",
    "cld":  "The CLD (Clear Direction Flag) instruction clears the direction flag, ensuring that string operations increment pointers. It specifically affects only the direction flag.",
    "std":  "The STD (Set Direction Flag) instruction sets the direction flag, causing string operations to decrement pointers. It modifies only the direction flag and leaves other flags unchanged."
}

#------------------------------------------------------------------------------
# Custom Context Menu Action Handler
#------------------------------------------------------------------------------
class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

#------------------------------------------------------------------------------
# Web lookup: Fetch an opcode explanation from Felix Cloutier's x86 reference.
#------------------------------------------------------------------------------
def get_opcode_description(mnemonic):
    """
    Given an opcode mnemonic, first check the local dictionary.
    If not found locally, fetch its explanation from the web resource.
    """
    mnemonic_lower = mnemonic.lower()
    if mnemonic_lower in local_opcode_descriptions:
        return local_opcode_descriptions[mnemonic_lower]
    
    base_url = "https://www.felixcloutier.com/x86/"
    url = base_url + mnemonic_lower
    try:
        with urllib.request.urlopen(url) as response:
            html = response.read().decode('utf-8')
        match = re.search(r'<p>(.*?)</p>', html, re.DOTALL)
        if match:
            description = re.sub(r'<[^>]+>', '', match.group(1))
            return description.strip()
        else:
            return "No description found on the web resource for opcode '{}'.".format(mnemonic)
    except Exception as e:
        return "Error fetching description for opcode '{}': {}".format(mnemonic, e)

#------------------------------------------------------------------------------
# Opcode Explanation Action Function
#------------------------------------------------------------------------------
def explain_opcode_py3():
    """
    Retrieves the mnemonic at the current address, fetches its explanation 
    (from local data if available, otherwise from the web), and displays the result.
    """
    ea = idc.here()
    if ea == idaapi.BADADDR:
        idaapi.msg("No valid address found.\n")
        return

    mnem = idaapi.print_insn_mnem(ea)
    if not mnem:
        idaapi.msg("No instruction found at 0x%X\n" % ea)
        return

    key = mnem.lower()
    if key in opcode_cache:
        explanation = opcode_cache[key]
    else:
        explanation = get_opcode_description(mnem)
        opcode_cache[key] = explanation

    idaapi.info("Opcode: {}\n\nExplanation:\n{}".format(mnem, explanation))

#------------------------------------------------------------------------------
# Injection Function: Insert "Explain Opcode" into the popup menu.
#------------------------------------------------------------------------------
def inject_explain_opcode_action(form, popup, form_type):
    if form_type == idaapi.BWN_DISASMS:
        idaapi.attach_action_to_popup(
            form, popup,
            opcode_explainer.ACTION_EXPLAIN_OPCODE,
            "Explain Opcode",
            idaapi.SETMENU_APP
        )
    return 0

#------------------------------------------------------------------------------
# UI Hooks: Use IDA's UI_Hooks to inject our menu item.
#------------------------------------------------------------------------------
class OpcodeHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        inject_explain_opcode_action(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def finish_populating_tform_popup(self, form, popup):
        inject_explain_opcode_action(form, popup, idaapi.get_tform_type(form))
        return 0

    def hxe_callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args
            idaapi.attach_action_to_popup(
                form, popup,
                opcode_explainer.ACTION_EXPLAIN_OPCODE,
                "Explain Opcode",
                idaapi.SETMENU_APP
            )
        return 0

#------------------------------------------------------------------------------
# Plugin: Opcode Explainer (Web with Local Cache)
#------------------------------------------------------------------------------
class opcode_explainer(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Provides a web-based explanation for x86 instructions. For 50 common opcodes, local data (including flag effects) is used."
    help = "Highlight an instruction, right-click, and select 'Explain Opcode' to fetch a description."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    ACTION_EXPLAIN_OPCODE = "opcode_explainer:explain_opcode"

    def init(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_EXPLAIN_OPCODE,
            "Explain Opcode",
            IDACtxEntry(explain_opcode_py3),
            PLUGIN_HOTKEY,
            "Fetch and explain what this opcode does (local data for common opcodes)",
            0
        )
        if not idaapi.register_action(action_desc):
            idaapi.msg("Failed to register action.\n")
            return idaapi.PLUGIN_SKIP

        self._hooks = OpcodeHooks()
        self._hooks.hook()
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        self._hooks.unhook()
        idaapi.unregister_action(self.ACTION_EXPLAIN_OPCODE)
        idaapi.msg("%s terminated...\n" % self.wanted_name)

def PLUGIN_ENTRY():
    return opcode_explainer()
