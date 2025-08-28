# Authority.py
from fileinput import filename

from FileKeyStore import FileKeyStore
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from phe import paillier, EncryptedNumber
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    handlers=[logging.FileHandler("python_logs.log", encoding="utf-8"),
              logging.StreamHandler()],
    force=True,  # <— importante con uvicorn
)

logger = logging.getLogger(__name__)

class PublicKeyResponse(BaseModel):
    n: str
    g: str
    pk_fingerprint: str

class DecryptTallyModel(BaseModel):
    votazione_id: int
    ciphertext_sum: int

class DecryptTallyResponse(BaseModel):
    plain_sum: int

class CreateElectionModel(BaseModel):
    votazione_id: int

class Authority:
    """
    Authority che gestisce chiavi per-elezione, persistite su file.
    """

    def __init__(self, keystore_path: str):
        self.router = APIRouter()
        self.store = FileKeyStore(keystore_path)
        self.router.post("/api/elections")(self.create_election)
        self.router.post("/api/elections/decrypt_tally")(self.decrypt_tally)


    async def create_election(self, request: Request, n_length: int = 2048, overwrite: bool = False) -> PublicKeyResponse:
        # idempotente: se esiste e overwrite=False, restituisce solo la PK
        try:
            resp = await request.json()
            create_model = CreateElectionModel(**resp)
            votazione_id = create_model.votazione_id

            if self.store.has(str(votazione_id)) and not overwrite:
                logger.info(f"VOTAZIONE {votazione_id} Chiave esistente...")
                pk, _ = self.store.get(str(votazione_id))
                logger.info(f"Chiave resituita: {pk}")
                return PublicKeyResponse(
                n=str(pk.n),
                g=str(getattr(pk, "g", 1)),
                pk_fingerprint=self.public_key_fingerprint(str(votazione_id)),
            )
            logger.info(f"VOTAZIONE {votazione_id} Creazione chiave...")
            pk, sk = paillier.generate_paillier_keypair(n_length=n_length)
            self.store.set(str(votazione_id), pk, sk)
            logger.info(f"Chiave resituita: {pk}")
            return PublicKeyResponse(
                n=str(pk.n),
                g=str(getattr(pk, "g", 1)),
                pk_fingerprint=self.public_key_fingerprint(str(votazione_id)),
            )
        except Exception as e:
            logging.info(f"create_election error: {e}")
            raise HTTPException(status_code=500, detail=str(e))


    async def decrypt_tally(self, request: Request) -> DecryptTallyResponse:
        try:
            body_json = await request.json()
            body = DecryptTallyModel(**body_json)

            votazione_id = body.votazione_id
            ciphertext_sum = body.ciphertext_sum
            pk, sk = self.store.get(str(votazione_id))
            enc_sum = EncryptedNumber(pk, ciphertext_sum, 0)

            return DecryptTallyResponse(
                plain_sum=sk.decrypt(enc_sum)
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def public_key_fingerprint(self, votazione_id: str) -> str:
        import hashlib
        pk, _ = self.store.get(votazione_id)
        g = getattr(pk, "g", 1)
        return hashlib.sha256(f"{pk.n}:{g}".encode()).hexdigest()
