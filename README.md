# pluto-chat
 PlutoChat is a real-time chat application establishing digital wireless communication between two Adalm Pluto SDRs
python3 -m venv .venv
python -m pip install -U pip setuptools wheel
python -m pip install numpy scipy matplotlib pyadi-iio pylibiio scikit-dsp-comm cryptography

Encryption:
- Caesar is used by default.
- AES-128 can be selected in Change Radio Parameters -> Encryption Protocol.
- Both PCs must use the same protocol and the same AES-128 password.
