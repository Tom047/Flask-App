# Flask-App
Flask Application to parse Solana NFT's info

## Installation
<ol>
  <li> You need to pip install additional packages to your environment: </li>
  json2html, psycopg2, flask, requests
  <li> After installing the necessary libraries, install PostgreSQL.</li>
  <li> Download project(src folder) to your PC and connect it to your database (change the conn variable in the project.py file).</li>
  <li> Launch project.py and open the address http://127.0.0.1:5000 in the browser</li>
</ol>

## Usage
In the only input field on the page, paste the NFT address on the Solana blockchain and press Enter or click on the search button.

![image](https://user-images.githubusercontent.com/99247067/196034123-98ea2609-8592-42dd-bb37-bdea13aa45dd.png)

After a short loading, in the next page you will receive a table with information about this NFT.

![image](https://user-images.githubusercontent.com/99247067/196034347-ad1abf8e-a3db-4542-b21c-e9cf61892e9f.png)

If there is no NFT with this address on the Solana blockchain, you will receive the message "NFT with this address not found"
