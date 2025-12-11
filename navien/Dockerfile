FROM python:3.11-slim

WORKDIR /usr/src/app

# 코드 복사
COPY test.py .
COPY run.sh .
COPY requirements.txt .

# 의존성 설치
RUN pip install --no-cache-dir -r requirements.txt

# 실행 권한 부여
RUN chmod +x run.sh

CMD ["/usr/src/app/run.sh"]
