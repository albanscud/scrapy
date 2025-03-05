import scrapy
import re

class RewtersSpider(scrapy.Spider):
    name = "rewters_spider"
    allowed_domains = ["rewterz.com"]
    start_urls = ["https://rewterz.com/threat-advisory"]

    def parse(self, response):
        # Extraire tous les liens des articles
        article_links = response.css('article.post .post-title a::attr(href)').getall()

        for link in article_links:
            # Suivre chaque lien vers la page de détail de l'article
            yield response.follow(link, callback=self.parse_ioc_page)

    def parse_ioc_page(self, response):
        iocs = []
        
        # Essayer d'extraire les IOCs en utilisant des XPath plus robustes
        ioc_texts = response.xpath("//p/text() | //li/text() | //code/text()").getall()
        
        for text in ioc_texts:
            value = text.strip()
            ioc_type = self.classify_ioc(value)
            if ioc_type != "Unknown":
                iocs.append({"type": ioc_type, "value": value})
        
        for ioc in iocs:
            yield ioc

    def classify_ioc(self, value):
        if self.is_md5(value):
            return "MD5"
        elif self.is_sha1(value):
            return "SHA-1"
        elif self.is_sha256(value):
            return "SHA-256"
        elif self.is_ip(value):
            return "IP"
        elif self.is_domain(value):
            return "Domain"
        elif self.is_url(value):
            return "URL"
        else:
            return "Unknown"

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
        return re.match(r"^(https?://[^']+)$", value) is not None

