import scrapy
import re
from datetime import datetime

class RewtersSpider(scrapy.Spider):
    name = "rewters_spider"
    allowed_domains = ["rewterz.com"]
    start_urls = ["https://rewterz.com/threat-advisory"]

    def parse(self, response):
        # Extraction des liens des articles
        article_links = response.css('article.post .post-title a::attr(href)').getall()

        for link in article_links:
            yield response.follow(link, callback=self.parse_ioc_page)

    def parse_ioc_page(self, response):
        # Extraction du titre et filtrage
        title = response.css("h1.entry-title::text").get(default="").strip()
        if "IOC" not in title.upper():  # Vérifie si "IOC" est dans le titre
            return

        # Extraction des autres métadonnées
        raw_date = response.css("span.post-date.updated::text").get(default="").strip()
        date = self.format_date(raw_date)

        # Récupération de la vraie description unique
        paragraphs = response.css("div.column_attr p::text").getall()
        paragraphs = [p.strip() for p in paragraphs if len(p.strip()) > 50]  # Exclure les phrases trop courtes
        body = " ".join(paragraphs[:5]) if paragraphs else ""
        
        # Suppression du texte indésirable s'il est présent
        body = re.sub(r"Rewterz penetration testing services.*?in good hands\.", "", body, flags=re.DOTALL).strip()

        # Extraction des IOCs
        iocs = {
            "md5": [],
            "sha256": [],
            "sha1": [],
            "ip": [],
            "domain": [],
            "url": []
        }

        ioc_texts = response.xpath("//p/text() | //li/text() | //code/text()").getall()
        
        for text in ioc_texts:
            value = text.strip()
            ioc_type = self.classify_ioc(value)
            if ioc_type in iocs:
                iocs[ioc_type].append(value)

        # Déduction automatique des tags en fonction des IOCs
        tags = self.get_tags(iocs, title)

        # Génération du format de sortie JSON
        yield {
            "title": title,
            "body": body,
            "date": date,
            "tags": ",".join(tags),
            "md5": ",".join(iocs["md5"]),
            "sha256": ",".join(iocs["sha256"]),
            "sha1": ",".join(iocs["sha1"]),
            "ip": ",".join(iocs["ip"]),
            "domain": ",".join(iocs["domain"]),
            "url": ",".join(iocs["url"]),
        }

    def format_date(self, raw_date):
        """Convertit une date en format ISO 8601"""
        try:
            return datetime.strptime(raw_date, "%B %d, %Y").strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return ""

    def classify_ioc(self, value):
        """Classifie les IOCs selon leur format"""
        if self.is_md5(value):
            return "md5"
        elif self.is_sha1(value):
            return "sha1"
        elif self.is_sha256(value):
            return "sha256"
        elif self.is_ip(value):
            return "ip"
        elif self.is_domain(value):
            return "domain"
        elif self.is_url(value):
            return "url"
        return "unknown"

    def get_tags(self, iocs, title):
        """Déduit les tags en fonction des types d'IOCs détectés et du titre"""
        tags = set()

        if "malware" in title.lower() or iocs["md5"] or iocs["sha1"] or iocs["sha256"]:
            tags.add("malware")
        if "network" in title.lower() or iocs["ip"] or iocs["domain"]:
            tags.add("network")
        if "phishing" in title.lower() or iocs["url"]:
            tags.add("phishing")
        if "ransomware" in title.lower():
            tags.add("ransomware")

        return list(tags)

    def is_md5(self, value):
        return re.match(r"^[a-fA-F0-9]{32}$", value) is not None

    def is_sha1(self, value):
        return re.match(r"^[a-fA-F0-9]{40}$", value) is not None

    def is_sha256(self, value):
        return re.match(r"^[a-fA-F0-9]{64}$", value) is not None

    def is_ip(self, value):
        return re.match(r"^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$", value) is not None

    def is_domain(self, value):
        return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value) is not None

    def is_url(self, value):
        return re.match(r"^(https?://[^\s]+)$", value) is not None

'''
#TOUT LES IOC
import scrapy
import re
from datetime import datetime

class RewtersSpider(scrapy.Spider):
    name = "rewters_spider"
    allowed_domains = ["rewterz.com"]
    start_urls = ["https://rewterz.com/threat-advisory"]

    def parse(self, response):
        # Extraction des liens des articles
        article_links = response.css('article.post .post-title a::attr(href)').getall()

        for link in article_links:
            yield response.follow(link, callback=self.parse_ioc_page)

    def parse_ioc_page(self, response):
        # Extraction des métadonnées
        title = response.css("h1.entry-title::text").get(default="").strip()
        raw_date = response.css("span.post-date.updated::text").get(default="").strip()
        date = self.format_date(raw_date)

        description = response.css("div.column_attr p::text").get(default="").strip()

        tags = response.css("meta[name='keywords']::attr(content)").get(default="")
        tag_list = tags.split(",") if tags else []

        # Extraction des IOCs
        iocs = {
            "md5": [],
            "sha256": [],
            "sha1": [],
            "ip": [],
            "domain": [],
            "url": []
        }

        ioc_texts = response.xpath("//p/text() | //li/text() | //code/text()").getall()
        
        for text in ioc_texts:
            value = text.strip()
            ioc_type = self.classify_ioc(value)
            if ioc_type in iocs:
                iocs[ioc_type].append(value)

        # Génération du format de sortie JSON
        yield {
            "title": title,
            "body": description,
            "date": date,
            "tags": ",".join(tag_list),
            "md5": ",".join(iocs["md5"]),
            "sha256": ",".join(iocs["sha256"]),
            "sha1": ",".join(iocs["sha1"]),
            "ip": ",".join(iocs["ip"]),
            "domain": ",".join(iocs["domain"]),
            "url": ",".join(iocs["url"]),
        }

    def format_date(self, raw_date):
        """Convertit une date en format ISO 8601"""
        try:
            return datetime.strptime(raw_date, "%B %d, %Y").strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return ""

    def classify_ioc(self, value):
        """Classifie les IOCs selon leur format"""
        if self.is_md5(value):
            return "md5"
        elif self.is_sha1(value):
            return "sha1"
        elif self.is_sha256(value):
            return "sha256"
        elif self.is_ip(value):
            return "ip"
        elif self.is_domain(value):
            return "domain"
        elif self.is_url(value):
            return "url"
        return "unknown"

    def is_md5(self, value):
        return re.match(r"^[a-fA-F0-9]{32}$", value) is not None

    def is_sha1(self, value):
        return re.match(r"^[a-fA-F0-9]{40}$", value) is not None

    def is_sha256(self, value):
        return re.match(r"^[a-fA-F0-9]{64}$", value) is not None

    def is_ip(self, value):
        return re.match(r"^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$", value) is not None

    def is_domain(self, value):
        return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value) is not None

    def is_url(self, value):
        return re.match(r"^(https?://[^\s]+)$", value) is not None
'''
