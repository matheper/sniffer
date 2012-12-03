# -*- coding:utf-8 -*-
#!/usr/bin/python
import sys, time
import threading

try:
    import pygtk
    pygtk.require("2.0")
except:
    print "Erro require pygtk >= 2.0."
    sys.exit(1)
try:
    import gtk
    import gtk.glade
except:
    print "Erro ao importar o GTK."
    sys.exit(1)
try:
    from sniffer import Sniffer
except:
    print "Erro ao importar sniffer."
    sys.exit(1)


class App(object):
    """Sniffer Interface
    """

    def __init__(self):
        #carrega o arquivo Glade
        self.appglade = "app.glade"
        #carrega xml
        self.xml = gtk.glade.XML(self.appglade)
        self.xml.signal_autoconnect(self)

        #Campo Tree
        self.lstConsulta = self.xml.get_widget("lstConsulta")
        self.entryFilter = self.xml.get_widget("entry1")
        self.lstConsulta.set_headers_visible(True)
        self.sniffer = Sniffer()
        self.format_grid()
        self.capturing = False

        # carrega botoes
        self.btnIniciar = self.xml.get_widget("btnIniciar")
        self.btnParar = self.xml.get_widget("btnParar")
        self.btnCarregar = self.xml.get_widget("btnCarregar")
        self.btnEstatisticas = self.xml.get_widget("btnEstatisticas")
        self.btnGraficos = self.xml.get_widget("btnGraficos")
        self.btnLimparCaptura = self.xml.get_widget("btnLimparCaptura")
        self.btnFiltrar = self.xml.get_widget("btnFiltrar")
        self.btnLimpar = self.xml.get_widget("btnLimpar")
        self.set_buttons()

    def start(self, widget, data):
        """ Inicia a captura dos pacotes. """
        if not self.capturing:
            self.format_grid()
            self.capturing = True
            self.set_buttons()
            gtk.gdk.threads_init()
            cap = threading.Thread(target=self.capture)
            cap.start()
            

    def format_grid(self):
        #Formata controle lista
        self.ClearColunas()
        self.listbox_types = [str,str,str,str,str,str,str,str,str,str,str]
        self.listbox_data = self.sniffer.capture_list
        self.lstConsulta.set_model(self.get_dados(self.listbox_data, self.listbox_types))

        #Cria colunas da lista
        self.listbox_header = [ ('IP Origem',0), ('Tipo',1), ('IP Destino',2), ('Tipo',3),
                                ('Próximo Cabeçalho',4), ('Hop Limit',5),
                                ('Classe de Tráfego',6), ('',7), ('',8),
                                ('Flowlabel',9), ('Versão',10)
                              ]
        self.CriarColuna(self.listbox_header)

    def stop(self, widget, data):
        """ Para a captura dos pacotes. """
        if self.capturing:
            self.capturing = False
            self.set_buttons()

    def filter(self, widget, data):
        """ Filtra os pacotes. """
        self.listbox_data = self.sniffer.capture_filter(self.entryFilter.get_text())
        self.listbox_update()

    def clear(self, widget, data):
        """Limpa todos os filtros."""
        self.listbox_data = self.sniffer.capture_list
        self.listbox_update()

    def load(self, widget, data):
        """Carrega arquivo capture.cap."""
        self.sniffer.read_file('capture.cap')
        self.listbox_data = self.sniffer.capture_list
        self.listbox_update()

    def statistics(self, widget, data):
        """Abre janela com media de proximos cabecalhos e tabela de fluxo. """
        self.statsglade = "statistics.glade"
        self.statsxml = gtk.glade.XML(self.statsglade)
        self.lstStats = self.statsxml.get_widget("lstStatistics")

        for coluna in range(4):
            titulo = ""
            id = coluna
            renderer = gtk.CellRendererText()
            column = gtk.TreeViewColumn(titulo, renderer, text = id)
            column.set_resizable(False)
            self.lstStats.append_column(column)

        self.listStats_types = [str,str,str,str]
        self.listStats_data = self.sniffer.get_statistics()
        self.lstStats.set_model(self.get_dados(self.listStats_data, self.listStats_types))
        print "teste"

    def graphcs(self, widget, data):
        """Dispara acao que abre nova janela com graficos. """
        self.open_graphs()

    def captureClear(self, widget, data):
        """Limpa listas de captura do sniffer. """
        self.sniffer.clearAll()
        self.listbox_data = self.sniffer.capture_list
        self.listbox_update()

    def quitMainWindow(self, widget, data):
        """ Sai do loop principal de eventos, finalizando o programa. """
        gtk.main_quit()

    def CriarColuna(self, colunas):
        """ Cria coluna da lista
        """
        for coluna in colunas:
            titulo = coluna[0]
            id = coluna[1]
            renderer = gtk.CellRendererText()
            column = gtk.TreeViewColumn(titulo, renderer, text = id)
            column.set_resizable(False)
            self.lstConsulta.append_column(column)

    def ClearColunas(self):
        """ Limpa colunas da lista. """
        for coluna in self.lstConsulta.get_columns():
            self.lstConsulta.remove_column(coluna)

    def listbox_update(self):
        """Atualiza dados da listbox. """
        self.lstConsulta.set_model(self.get_dados(self.listbox_data, self.listbox_types))

    def get_dados(self,dados,types):
        """ Adiciona as linhas nas respectivas colunas da listbox."""
        retorno = gtk.ListStore(*types)
        for dado in dados:
            retorno.append(dado)
        return retorno

    def capture(self):
        """ Captura pacotes da rede. """
        while self.capturing:
            self.sniffer.get_packet()
            self.listbox_data = self.sniffer.capture_list
            self.listbox_update()

    def open_graphs(self):
        """ Carrega graficos gerados pelo sniffer em uma nova janela. """
        self.sniffer.create_graphs()
        self.graphsglade = "graphs.glade"
        self.graphsxml = gtk.glade.XML(self.graphsglade)
        address = self.graphsxml.get_widget("addressType")
        address.set_from_file('addressType.svg')
        traffic = self.graphsxml.get_widget("trafficClass")
        traffic.set_from_file('trafficClass.svg')
        icmpv6 = self.graphsxml.get_widget("lenNextHeader")
        icmpv6.set_from_file('lenNextHeader.svg')
        nextHeader = self.graphsxml.get_widget("nextHeader")
        nextHeader.set_from_file('nextHeader.svg')

    def set_buttons(self):
        """Ativa ou desativo os botoes de captura e filtro. """
        if self.capturing:
            self.btnIniciar.set_state(gtk.STATE_INSENSITIVE)
            self.btnParar.set_sensitive(True)
            self.btnCarregar.set_state(gtk.STATE_INSENSITIVE)
            self.btnEstatisticas.set_state(gtk.STATE_INSENSITIVE)
            self.btnGraficos.set_state(gtk.STATE_INSENSITIVE)
            self.btnLimparCaptura.set_state(gtk.STATE_INSENSITIVE)
            self.btnFiltrar.set_state(gtk.STATE_INSENSITIVE)
            self.btnLimpar.set_state(gtk.STATE_INSENSITIVE)
        else:
            self.btnIniciar.set_sensitive(True)
            self.btnParar.set_state(gtk.STATE_INSENSITIVE)
            self.btnCarregar.set_sensitive(True)
            self.btnEstatisticas.set_sensitive(True)
            self.btnGraficos.set_sensitive(True)
            self.btnLimparCaptura.set_sensitive(True)
            self.btnFiltrar.set_sensitive(True)
            self.btnLimpar.set_sensitive(True)


if __name__ == "__main__":
    app = App()
    gtk.main()
