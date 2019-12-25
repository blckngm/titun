import React, { useState, useEffect } from 'react';
import { InterfaceState } from './InterfaceState';
import { makeStyles } from '@material-ui/core';

const useStyles = makeStyles((theme) => ({
    root: {
        fontFamily: 'Consolas, monospace',
        fontSize: 'large',
        '& p': {
            marginTop: '.3em',
            marginBottom: 0,
        },
    },
    bold: {
        fontWeight: 'bold',
    },
    green: {
        color: 'green',
    },
    darkGreen: {
        color: 'darkgreen',
    },
    yellow: {
        color: 'rgb(165, 165, 8)',
    },
    darkYellow: {
        color: 'rgb(117, 117, 18)',
    },
    cyan: {
        color: 'rgb(13, 130, 130)',
    }
}));

function kv(k: string, v: string | JSX.Element): JSX.Element {
    return <p>&nbsp;&nbsp;<b>{k}</b>: {v}</p>;
}

function joinJSX(delimiter: JSX.Element | string, xs: (JSX.Element | string | undefined | null)[]): JSX.Element | string | null | undefined {
    return xs.reduce((acc, x) => {
        if (!acc) {
            return x;
        }
        if (!x) {
            return acc;
        }
        return <>{acc!}{delimiter}{x!}</>;
    });
}

interface ShowInterfaceStateProps {
    interfaceState: InterfaceState;
}

export default function ShowInterfaceState({interfaceState}: ShowInterfaceStateProps): JSX.Element {
    const [now, setNow] = useState(Math.trunc(new Date().getTime() / 1000));
    useEffect(() => {
        const i = setInterval(() => {
            setNow(Math.trunc(new Date().getTime() / 1000));
        }, 1000);
        return () => clearInterval(i);
    }, []);

    const classes = useStyles();

    function humanSize(bytes: number): JSX.Element {
        if (bytes < 1024) {
            return <>{bytes} <span className={classes.cyan}>B</span></>;
        } else if (bytes < 1024 * 1024) {
            const kib = bytes / 1024;
            return <>{kib.toFixed(2)} <span className={classes.cyan}>KiB</span></>;
        } else if (bytes < 1024 * 1024 * 1024) {
            const mib = bytes / (1024 * 1024);
            return <>{mib.toFixed(2)} <span className={classes.cyan}>MiB</span></>;
        } else {
            const gib = bytes / (1024 * 1024 * 1024);
            return <>{gib.toFixed(2)} <span className={classes.cyan}>GiB</span></>;
        }
    }

    function humanTimeSpan(seconds: number): JSX.Element | undefined {
        const hours = Math.trunc(seconds / (60 * 60));
        const showHours = hours ? <>{hours} <span className={classes.cyan}>{hours > 1 ? "hours" : "hour"}</span></> : undefined;
        const minutes = Math.trunc(seconds / 60) % 60;
        const showMinutes = minutes ? <>{minutes} <span className={classes.cyan}>{minutes > 1 ? "minutes" : "minute"}</span></> : undefined;
        const secs = seconds % 60;
        const showSecs = secs ? <>{secs} <span className={classes.cyan}>{secs > 1 ? "seconds" : "second"}</span></> : undefined;
        return joinJSX(', ', [showHours, showMinutes, showSecs]) as JSX.Element | undefined;
    }

    function humanTimeAgo(seconds: number): JSX.Element {
        if (seconds === 0) {
            return <>just now</>;
        }

        return <>{humanTimeSpan(seconds)} ago</>;
    }

    return <div className={classes.root}>
        <p><span className={classes.green + ' ' + classes.bold}>interface</span>: <span className={classes.darkGreen}>{interfaceState.name}</span></p>
        {kv("public key", interfaceState.publicKey)}
        {kv("private key", "(hidden)")}
        {kv("listening port", interfaceState.listenPort.toString())}
        {interfaceState.peers.map((peer) => {
            return <React.Fragment key={peer.publicKey}>
                <br />
                <p><span className={classes.bold + ' ' + classes.yellow}>peer</span>: <span className={classes.darkYellow}>{peer.publicKey}</span></p>
                {peer.presharedKey ? kv("preshared key", "hidden") : undefined}
                {peer.endpoint && kv("endpoint", peer.endpoint)}
                {peer.allowedIps.length > 0 ?
                    kv("allowed ips", joinJSX(", ", peer.allowedIps.map((a) => {
                        return joinJSX(<span className={classes.cyan}>/</span>, a.split("/"));
                    }))!)
                : undefined}
                {peer.lastHandshakeTimeSec && kv("last handshake", humanTimeAgo(now - peer.lastHandshakeTimeSec))}
                {kv("transfer", <>{humanSize(peer.rxBytes)} received, {humanSize(peer.txBytes)} sent</>)}
                {peer.persistentKeepaliveInterval > 0 ?
                    kv("persistent keepalive", <>every {humanTimeSpan(peer.persistentKeepaliveInterval)}</>)
                    : undefined}
            </React.Fragment>;
        })}
    </div>;
}
