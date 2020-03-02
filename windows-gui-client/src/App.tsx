import React, { useState, useEffect, useRef, useLayoutEffect, useCallback } from 'react';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import { makeStyles } from '@material-ui/core';

import { run, stop, subscribeLog, getStatus, openFile, exit, hide } from './api';
import ShowInterfaceState from './ShowInterfaceState';
import { InterfaceState } from './InterfaceState';

const notIE = window.navigator.userAgent.indexOf("Trident") < 0;

const useStyles = makeStyles(theme => ({
    root: {
        flexGrow: 1,
    },
    menuButton: {
        marginRight: theme.spacing(2),
    },
    title: {
        flexGrow: 1,
    },
    status: {
        flexGrow: 1,
        overflow: 'auto',
        padding: theme.spacing(2),
    },
    showLogs: {
        flexGrow: 1,
        overflow: 'auto',
        padding: theme.spacing(2),
        '& pre': {
            fontSize: 'small',
            fontFamily: 'Consolas , monospace',
            margin: '.3em 0 0 0',
            padding: 0,
        },
        '& pre:last-child': {
            marginBottom: theme.spacing(2),
        }
    },
    lastLogLine: {
        flexShrink: 0,
        fontSize: 'small',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        fontFamily: 'Consolas, monospace',
        margin: theme.spacing(1),
        padding: theme.spacing(1),
        backgroundColor: '#7487f1',
    }
}));

const ShowLogs: React.FC<{ logLines: string[], className: string }> = ({ logLines, className }) => {
    const divRef = useRef<HTMLDivElement>(null);

    useLayoutEffect(() => {
        if (divRef.current) {
            const el = divRef.current;
            el.scrollTop = el.scrollHeight - el.clientHeight;
        }
    }, []);

    useLayoutEffect(() => {
        if (divRef.current) {
            const el = divRef.current;
            if (el.scrollHeight - el.scrollTop - el.clientHeight <= 20) {
                el.scrollTop = el.scrollHeight - el.clientHeight;
            }
        }
    }, [logLines]);

    return (<div className={className} ref={divRef}>
        {logLines.map((l) => <pre key={l}>{l}</pre>)}
    </div>
    );
}

const App: React.FC = () => {
    const classes = useStyles();

    const [running, setRunning] = useState(false);
    const [busy, setBusy] = useState(false);
    const [interfaceState, setInterfaceState] = useState<null | InterfaceState>(null);
    const [lastLogLine, setLastLogLine] = useState('');
    const [openLogs, setOpenLogs] = useState(false);
    const [logLines, setLogLines] = useState<string[]>([]);
    const [getStatusInterval, setGetStatusInterval] = useState<number>(0);
    const [openConfirmExit, setOpenConfirmExit] = useState(false);

    // Initial loading.
    useEffect(() => {
        getStatus().then((status) => {
            if (status != null) {
                setInterfaceState(status);
                setRunning(true);
                setGetStatusInterval(window.setInterval(async () => {
                    try {
                        setInterfaceState(await getStatus());
                    } catch (e) {
                        console.error(e);
                    }
                }, 1000));
            }
        }).catch(e => console.error(e));
    }, []);

    useEffect(() => {
        subscribeLog((logLine) => {
            console.info(logLine);
            setLogLines((old) => {
                if (old.length > 1024) {
                    return [...old.slice(256), logLine];
                }
                return [...old, logLine];
            });
            setLastLogLine(logLine);
        });
    }, []);

    const handleRunOrStopButtonClick = useCallback(async () => {
        setBusy(true);
        try {
            if (running) {
                await stop();
                setRunning(false);
                clearInterval(getStatusInterval);
                setLastLogLine('');
            } else {
                const fileName = await openFile();
                if (!fileName) {
                    return;
                }

                setLogLines([]);
                await run(fileName);
                setRunning(true);
                setGetStatusInterval(window.setInterval(async () => {
                    try {
                        setInterfaceState(await getStatus());
                    } catch (e) {
                        console.error(e);
                    }
                }, 1000));
            }
        } catch (e) {
            console.error(e);
        } finally {
            setBusy(false);
        }
    }, [running, getStatusInterval]);

    // Shortcut keys.
    useEffect(() => {
        const onKeyDown = (event: KeyboardEvent) => {
            console.debug(event);
            if ((notIE && event.target !== document.body) || event.cancelBubble) {
                return;
            }
            switch (event.key) {
                case 'q':
                case 'Q':
                    setOpenConfirmExit(true);
                    break;
                case 'Escape':
                case 'Esc': // IE.
                    hide();
                    break;
                case ' ':
                case 'Spacebar': // IE.
                case 'Enter':
                    handleRunOrStopButtonClick();
                    break;
            }
        };
        document.addEventListener('keydown', onKeyDown);
        return () => document.removeEventListener('keydown', onKeyDown);
    }, [handleRunOrStopButtonClick]);

    return <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        <AppBar position="static">
            <Toolbar>
                <Typography variant="h6" className={classes.title}>
                    TiTun
                </Typography>
                <Button
                    color="inherit"
                    disabled={busy}
                    onClick={handleRunOrStopButtonClick}
                >
                    {running ? "Stop" : "Run"}
                </Button>
                <Button color="inherit" onClick={() => setOpenConfirmExit(true)}>Exit</Button>
            </Toolbar>
        </AppBar>
        <Dialog open={openConfirmExit} onClose={() => setOpenConfirmExit(false)}>
            <DialogContent>
                <DialogContentText>
                    Exit TiTun?
                </DialogContentText>
            </DialogContent>
            <DialogActions>
                <Button color="primary" onClick={() => setOpenConfirmExit(false)}>No</Button>
                <Button color="primary" onClick={() => exit()} autoFocus>Yes</Button>
            </DialogActions>
        </Dialog>
        <Dialog fullScreen open={openLogs} onClose={() => setOpenLogs(false)}>
            <AppBar position="static">
                <Toolbar>
                    <Typography variant="h6" className={classes.title}>
                        Logs
                    </Typography>
                    <Button
                        color="inherit"
                        disabled={busy}
                        onClick={handleRunOrStopButtonClick}
                    >
                        {running ? "Stop" : "Run"}
                    </Button>
                    <Button color="inherit" onClick={() => setOpenLogs(false)}>Close</Button>
                </Toolbar>
            </AppBar>
            <ShowLogs logLines={logLines} className={classes.showLogs} />
        </Dialog>
        <div className={classes.status}>
            {running ?
                interfaceState ?
                    <ShowInterfaceState interfaceState={interfaceState} />
                    : "Loading interface status..."
                : undefined
            }
        </div>
        <div className={classes.lastLogLine} onClick={() => setOpenLogs(true)}>
            {lastLogLine || <br></br>}
        </div>
    </div>;
}

export default App;
