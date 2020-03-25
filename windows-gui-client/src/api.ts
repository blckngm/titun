import { InterfaceState, RtInterfaceState } from "./InterfaceState";
import { String, Null } from "runtypes";

(window as any).onLog = () => { };

let requestN = 0;

function nextRequest() {
    if (requestN === 0xffffffff) {
        requestN = 0;
        return 0xffffffff;
    }
    return requestN++;
}

function webviewRequest(request: { cmd: string, [x: string]: any }): Promise<any> {
    let n = nextRequest();
    const respnoseCb = 'responseCb' + n;
    (request as any).responseCb = respnoseCb;

    return new Promise((resolve, reject) => {
        (window as any)[respnoseCb] = (response: any) => {
            try {
                if (response?.error) {
                    reject(response?.error);
                } else {
                    resolve(response.data);
                }
            } finally {
                delete (window as any)[respnoseCb];
            }
        }
        (window as any).chrome.webview.postMessage(request);
    });
}

export async function openFile(): Promise<string | null> {
    const data = await webviewRequest({
        cmd: "openFile"
    });
    return String.Or(Null).check(data);
}

export async function run(configFilePath: string): Promise<void> {
    await webviewRequest({
        cmd: "run",
        configFilePath,
    });
}

export async function stop(): Promise<void> {
    await webviewRequest({
        cmd: "stop",
    });
}

export function subscribeLog(cb: (logLine: string) => void) {
    (window as any).onLog = (shouldBeLogLine: any) => {
        try {
            cb(String.check(shouldBeLogLine))
        } catch (e) {
            console.error(e);
        }
    };
}

export async function getStatus(): Promise<InterfaceState | null> {
    return webviewRequest({
        cmd: "getStatus"
    }).then((data) => RtInterfaceState.Or(Null).check(data));
}

export async function exit(): Promise<void> {
    await webviewRequest({
        cmd: "exit"
    });
}

export async function hide(): Promise<void> {
    await webviewRequest({
        cmd: "hide"
    });
}

export async function focus(): Promise<void> {
    await webviewRequest({
        cmd: "focus"
    });
}
