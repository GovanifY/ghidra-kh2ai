workflow "Build Extension" {
  on = "push"
  resolves = ["buildExtension"]
}

action "buildExtension" {
  uses = "govanify/ghidra-buildExtension@master"
}
