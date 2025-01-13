import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import os
import math
import pandas as pd

class Graphics:
    def __init__(self):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        plt.figure(figsize=(14, 7))
        plt.grid(color='gray', alpha=0.3, linewidth=0.5)
        plt.rcParams.update({
            'font.size': 20,       # Tamanho da fonte global
            'axes.labelsize': 20,  # Tamanho dos rótulos dos eixos
            'xtick.labelsize': 20, # Tamanho das etiquetas do eixo x
            'ytick.labelsize': 20, # Tamanho das etiquetas do eixo y
            'legend.fontsize': 20, # Tamanho da fonte da legenda
        })
    
    def heatmap(self, correlation_matrix, cmap='coolwarm', cbar=True):
        ax = sns.heatmap(correlation_matrix, annot=True, cmap=cmap, fmt='.2f')
        ax.set_ylabel('')
        ax.set_xlabel('')
        ax.tick_params(axis='x', rotation=45)
        
        output = os.path.join(f'{self.current_dir}/model_graphics/', "heatmap.pdf")
        plt.savefig(output, bbox_inches='tight')

    def groupedbar(self, df: pd.DataFrame, output_name: str, title: str, y_label: str, legend_title='', ncol = 5):
        plt.clf()
        data = df.to_dict(orient='list')
        labels = df.index.to_list()

        spacing_factor = 1.5
        x = np.arange(len(labels)) * spacing_factor
        width = 0.075
        multiplier = 0

        fig, ax = plt.subplots(figsize=(14, 10), layout='constrained')
        for column, values in data.items():
            offset = width * multiplier
            ax.bar(x + offset, values, width, label=f'{column}')
            multiplier +=1
        
        ax.set_ylabel(y_label)
        ax.set_title(title)
        ax.set_xticks(x + width * (len(data) - 1) / 2)
        ax.set_xticklabels(labels)
        ax.legend(title=legend_title, loc='upper center', bbox_to_anchor=(0.5, -0.1), ncol=ncol, frameon=False)

        output = os.path.join(f'{self.current_dir}/model_graphics/', f'{output_name}.pdf')
        plt.savefig(output, bbox_inches='tight')