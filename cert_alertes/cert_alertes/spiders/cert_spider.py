import scrapy
from cert_alertes.items import CertAlertItem

class CertSpider(scrapy.Spider):
    name = 'cert_spider'
    start_urls = ['https://www.cert.ssi.gouv.fr/alerte/']

    def parse(self, response):
        # Sélectionner tous les articles contenant les alertes
        for alerte in response.css('article.item.cert-alert.open'):
            item = CertAlertItem()
            # Extraire le titre
            item['titre'] = alerte.css('h3 a::text').get().strip()
            # Extraire la date
            item['date'] = alerte.css('span.item-date::text').get().strip()
            # Extraire la description (extrait de l'alerte)
            item['description'] = alerte.css('section.item-excerpt p::text').get().strip()
            # Extraire le lien
            item['lien'] = response.urljoin(alerte.css('h3 a::attr(href)').get())
            yield item

        # Si le site a une pagination, suivre le lien de la page suivante (s'il existe)
        next_page = response.css('a.next::attr(href)').get()
        if next_page:
            yield response.follow(next_page, self.parse)
