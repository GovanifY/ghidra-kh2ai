KH2AI
=====

KH2AI or, more specifically, ghidra-kh2ai, is a project implementing a
disassembler, assembler and a decompiler for Kingdom Hearts 2 
Artificial Intelligence's format. 
ghidra-kh2ai, as its name suggests, is developped for the Software Reverse
Engineering(SRE) framework Ghidra.

More informations about the project can be found at: govanify.com/TODO_BLOG

# Why Ghidra

Ghidra is factually better in its underlying architecture and easier to develop
for. If I targetted this tool to IDA I would have, at best, a disassembler and
trouble implementing a good bunch of what I did. SLEIGH, Ghidra's analyzer
architecture and extensions on top of the whole program architecture are just
better. RTFM.

# Dependancies

You will need a Ghidra development setup, or at the very least gradle and a
Ghidra installation somewhere on your storage space. You will also need a LaTeX
common build tools and extensions, pdflatex is preferred along with python to
build the manual.

# Building instructions

```
cd data/manuals/
mkdir sleigh
python generate_code.py ../languages/kh2ai.sinc
pdflatex kh2ai.tex
cd ../../
gradle -PGHIDRA_INSTALL_DIR=/my/ghidra/dir buildExtension
```

You will end up with an extension zip in the dist folder

# Can I have a tutorial on how to mod KH2 AI

put link to xaddgx video here

