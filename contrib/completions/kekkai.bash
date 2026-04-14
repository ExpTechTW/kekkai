# bash completion for kekkai
#
# Install to /usr/share/bash-completion/completions/kekkai (system-wide)
# or ~/.local/share/bash-completion/completions/kekkai (per-user).
#
# kekkai.sh install / repair / update installs this file automatically.
#
# Also works transparently after `sudo` thanks to bash-completion's
# __load_completion helper: when the user types `sudo kekkai <Tab>`,
# bash-completion detects kekkai as the command being sudo'd and loads
# this file.

_kekkai() {
    local cur prev words cword
    _init_completion || return

    local subcommands="status config check ports show backup reload bypass update reset doctor version help"

    # Top-level subcommand
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        return
    fi

    local sub="${words[1]}"
    case "$sub" in
        bypass)
            # `kekkai bypass on|off [--save] [config]`
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "on off" -- "$cur") )
                return
            fi
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--save" -- "$cur") )
                return
            fi
            _filedir
            return
            ;;
        reset)
            # `kekkai reset [config] [--iface NAME]`
            case "$prev" in
                --iface|-iface|-i)
                    # Offer active network interfaces if we can see them.
                    local ifaces=""
                    if [[ -d /sys/class/net ]]; then
                        ifaces="$(ls /sys/class/net 2>/dev/null | grep -v '^lo$')"
                    fi
                    COMPREPLY=( $(compgen -W "$ifaces" -- "$cur") )
                    return
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--iface" -- "$cur") )
                return
            fi
            _filedir
            return
            ;;
        update)
            # `kekkai update [kekkai.sh flags]`
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--force --no-install --iface --run" -- "$cur") )
                return
            fi
            ;;
        status|config|check|ports|show|backup|reload)
            # These all take an optional config path as the sole positional.
            _filedir
            return
            ;;
        doctor|version|help)
            # No args.
            return
            ;;
    esac
}

complete -F _kekkai kekkai
