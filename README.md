<h1 align="center">AnansiCapture</h1>
<p align="center">
<img alt="Static Badge" src="https://img.shields.io/badge/made_by-Definazu-red?style=for-the-badge&link=https%3A%2F%2Fgithub.com%2FDefinazu">
<img alt="GitHub License" src="https://img.shields.io/github/license/Definazu/AnansiCapture?style=for-the-badge">
<img alt="GitHub top language" src="https://img.shields.io/github/languages/top/Definazu/AnansiCapture?style=for-the-badge">
<img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/Definazu/AnansiCapture?style=for-the-badge">
</p>

## Definition
A simple cross-platform data traffic interception and analysis (NTA) tool written in Rust.

## Installation
### For Linux
> Firts of all you need install `npm`, `rustc`, `cargo`, `libpcap`.
1. **Copy** the repository and go to the root directory:

` git clone https://github.com/Definazu/AnansiCapture.git`

2. **Building** a project:

`cargo build`

Well done!

## Run
### CLI
`./target/debug/anansi -help`

### GUI
`cd gui`

`npm install`

`npm run tauri dev`