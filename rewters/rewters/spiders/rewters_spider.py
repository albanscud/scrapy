import scrapy
import re

class RewtersSpider(scrapy.Spider):
    name = "rewters_spider"
    allowed_domains = ["rewterz.com"]
    start_urls = [
        'https://rewterz.com/threat-advisory',  # URL de la page principale
    ]

    def parse(self, response):
        # Extraire tous les liens des articles
        article_links = response.css('article.post .post-title a::attr(href)').getall()

        for link in article_links:
            # Suivre chaque lien vers la page de détail de l'article
            yield response.follow(link, callback=self.parse_ioc_page)

    def parse_ioc_page(self, response):
        # Initialisation d'une liste pour stocker les IOCs
        iocs = []

        # Extraction des IOCs MD5
        md5_iocs = response.css('h4.wp-block-heading:contains("MD5") + ul li p::text').getall()
        for md5 in md5_iocs:
            iocs.append({'type': 'MD5', 'value': md5.strip()})

        # Extraction des IOCs SHA-256
        sha256_iocs = response.css('h4.wp-block-heading:contains("SHA-256") + ul li p::text').getall()
        for sha256 in sha256_iocs:
            iocs.append({'type': 'SHA-256', 'value': sha256.strip()})

        # Extraction des IOCs SHA-1
        sha1_iocs = response.css('h4.wp-block-heading:contains("SHA-1") + ul li p::text').getall()
        for sha1 in sha1_iocs:
            iocs.append({'type': 'SHA-1', 'value': sha1.strip()})

        # Retourner chaque IOC trouvé dans la page
        for ioc in iocs:
            yield ioc

    def classify_ioc(self, value):
        """Classifie le type de l'IOC"""
        if self.is_url(value):
            return "URL"
        elif self.is_domain(value):
            return "Domain"
        elif self.is_ip(value):
            return "IP"
        elif self.is_hash(value):
            return "Hash"
        else:
            return "Unknown"

    def is_url(self, value):
        """Vérifie si c'est une URL"""
        url_pattern = r"^(https?://[^\s]+)$"
        return re.match(url_pattern, value) is not None

    def is_domain(self, value):
        """Vérifie si c'est un domaine"""
        domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(domain_pattern, value) is not None

    def is_ip(self, value):
        """Vérifie si c'est une IP"""
        ip_pattern = r"^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$"
        return re.match(ip_pattern, value) is not None

    def is_hash(self, value):
        """Vérifie si c'est un hash (MD5, SHA1, SHA256)"""
        hash_patterns = [
            r"^[a-fA-F0-9]{32}$",  # MD5
            r"^[a-fA-F0-9]{40}$",  # SHA1
            r"^[a-fA-F0-9]{64}$",  # SHA256
        ]
        return any(re.match(pattern, value) for pattern in hash_patterns)
