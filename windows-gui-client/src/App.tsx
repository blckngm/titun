import React, { useState, useEffect } from 'react';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import { makeStyles } from '@material-ui/core';

import { run, stop, subscribeLog, getStatus, openFile, exit } from './api';
import ShowInterfaceState from './ShowInterfaceState';
import { InterfaceState } from './InterfaceState';

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

const App: React.FC = () => {
    const classes = useStyles();

    const [running, setRunning] = useState(false);
    const [busy, setBusy] = useState(false);
    const [interfaceState, setInterfaceState] = useState<null | InterfaceState>(null);
    const [lastLogLine, setLastLogLine] = useState('');
    const [showLogs, setShowLogs] = useState(false);
    const [logLines, setLogLines] = useState<string[]>([]);
    const [getStatusInterval, setGetStatusInterval] = useState<number>(0);

    // Initial loading.
    useEffect(() => {
        getStatus().then((status) => {
            if (status != null) {
                setInterfaceState(status);
                setRunning(true);
                setGetStatusInterval(setInterval(async () => {
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

    const handleRunOrStopButtonClick = async () => {
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
                setGetStatusInterval(setInterval(async () => {
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
    };

    const closeShowLogs = () => setShowLogs(false);
    const handleExit = () => exit();

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
                <Button color="inherit" onClick={handleExit}>Exit</Button>
            </Toolbar>
        </AppBar>
        <Dialog fullScreen open={showLogs} onClose={closeShowLogs}>
            <AppBar position="static">
                <Toolbar>
                    <Typography variant="h6" className={classes.title}>
                        Logs
                    </Typography>
                    <Button color="inherit" onClick={closeShowLogs}>Close</Button>
                </Toolbar>
            </AppBar>
            <div className={classes.showLogs}>
                {logLines.map((l) => <pre key={l}>{l}</pre>)}
            </div>
        </Dialog>
        <div className={classes.status}>
            {running ?
                interfaceState ?
                    <ShowInterfaceState interfaceState={interfaceState} />
                    : "Loading interface status..."
                : undefined
            }
        </div>
        <div className={classes.lastLogLine} onClick={() => setShowLogs(true)}>
            {lastLogLine || <br></br>}
        </div>
    </div>;
}

export default App;
