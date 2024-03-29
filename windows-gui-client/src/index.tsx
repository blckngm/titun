import React from 'react';
import ReactDOM from 'react-dom';
import { ThemeProvider, createMuiTheme } from '@material-ui/core/styles';

import './style.css';
import App from './App';
import { focus } from './api';

const theme = createMuiTheme({
    typography: {
      fontFamily: '"Segoe UI", Helvetica, Arial, sans-serif'
    },
});

focus().catch(e => console.error(e));

// Render after DOMContentLoaded so that this works in inline script.
document.addEventListener("DOMContentLoaded", () => {
    ReactDOM.render(
        <ThemeProvider theme={theme}>
            <App />
        </ThemeProvider>,
        document.getElementById("root")
    );
});
