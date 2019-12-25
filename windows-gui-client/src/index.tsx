import 'react-app-polyfill/ie11';
import 'core-js/features/math/trunc';

import React from 'react';
import ReactDOM from 'react-dom';
import { ThemeProvider, createMuiTheme } from '@material-ui/core/styles';

import './style.css';
import App from './App';

const theme = createMuiTheme({
    typography: {
      fontFamily: '"Segoe UI", Helvetica, Arial, sans-serif'
    },
});

ReactDOM.render(<ThemeProvider theme={theme}><App /></ThemeProvider>, document.getElementById('root'));
