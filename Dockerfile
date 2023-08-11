#Deriving the python 3.11 base image
FROM python:3.11-bullseye

#Labels as key value pair
LABEL Maintainer="mattia.bencivenga"

# Any working directory can be chosen as per choice like '/' or '/home' etc
# i have chosen /usr/app
WORKDIR /usr/app

COPY requirements.txt .
RUN pip install -r requirements.txt

#to COPY the remote file at working directory in container
COPY . .

RUN mkdir Policy output

EXPOSE 5000

CMD [ "python", "./orchestrator.py"]
