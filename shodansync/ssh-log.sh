# shellcheck shell=sh
datestr=$(date +%s)
echo "$datestr name=$1 cmd=$SSH_ORIGINAL_COMMAND" >> "$HOME/.ssh/ssh.log"
exit 1
