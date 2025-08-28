from phe import paillier
import json, os, tempfile
from typing import Dict, Tuple, Optional
from pathlib import Path

class FileKeyStore:
    """
    Keystore su file (JSON).
    Struttura:
    {
      "elections": {
        "<election_id>": { "n": "...", "g": "...", "p": "...", "q": "..." }
      }
    }
    """
    def __init__(self, path: str | os.PathLike = "keys.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            with open(self.path, "w", encoding="utf-8") as f:
                f.write("{}")

    def _read(self) -> Dict:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                txt = f.read().strip()
                if not txt:
                    return {}
                return json.loads(txt)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            # file corrotto: riparti pulito (o logga e rilancia)
            return {}

    def _atomic_write(self, data: Dict):
        # scrittura atomica: write -> rename
        tmpf = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmpf.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmpf, self.path)

    def has(self, election_id: str) -> bool:
        data = self._read()
        return election_id in data.get("elections", {})

    def set(self, election_id: str, pk: paillier.PaillierPublicKey, sk: paillier.PaillierPrivateKey):
        data = self._read()
        data.setdefault("elections", {})[election_id] = {
            "n": str(pk.n),
            "g": str(getattr(pk, "g", 1)),
            # per ricostruire la private key in phe servono p e q
            "p": str(getattr(sk, "p", None)),
            "q": str(getattr(sk, "q", None)),
        }
        self._atomic_write(data)

    def get(self, election_id: str) -> Tuple[paillier.PaillierPublicKey, paillier.PaillierPrivateKey]:
        data = self._read()
        rec = data.get("elections", {}).get(election_id)
        if not rec:
            raise KeyError(f"Chiavi non trovate per election_id={election_id}")
        n = int(rec["n"])
        g = int(rec.get("g", 1))
        p = int(rec["p"])
        q = int(rec["q"])
        pk = paillier.PaillierPublicKey(n)
        sk = paillier.PaillierPrivateKey(pk, p, q)
        return pk, sk
