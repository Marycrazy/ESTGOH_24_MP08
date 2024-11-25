{ pkgs ? import <nixpkgs> {} }:

let
    pythonEnv = pkgs.python3.withPackages (ps: with ps; [ pip ]);
in
pkgs.mkShell {
    buildInputs = [
        pythonEnv
        pkgs.tree
        pkgs.firefox
    ];

    shellHook = ''
        export PYTHONPATH=$PYTHONPATH:$(pwd)

        python3 -m venv .venv
        source .venv/bin/activate

        cd vulnerable_app

        pip install -r requirements.txt

        alias cls='clear'
        alias runserver='python app.py'
        alias up='cd ..; docker-compose up -d; cd vulnerable_app'
        alias open='firefox http://127.0.0.1:9000'
    '';
}