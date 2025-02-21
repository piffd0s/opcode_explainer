# opcode_explainer
IDA Plugin for explaining opcodes, this is the plugin I wish I had when I was learning assembly and reverse engineering

## Using opcode_explainer
Highlight the opcode that you want to explain in the disassembly window then right click and select `Explain Opcode`. You can also use the `Ctrl+E` hotkey to explain the selected opcode. 

The explanation for the top 50 opcodes is in the python script, any really obscure opcodes will be loaded via a web request to https://www.felixcloutier.com/x86/ 

## Installing opcode_explainer
Simply copy the latest release of opcode_explainer into your IDA plugins directory and you are ready to start learning assembly!

## ❗Compatibility Issues
opcode_explainer has been developed for use with the __IDA 7+__ and __Python 3__. 

I know many of you are still using Python 2.7 for compatibility with older plugins. We will attempt to continue to support Python 2.7 on IDA 7+ but there are no guarantees. 
