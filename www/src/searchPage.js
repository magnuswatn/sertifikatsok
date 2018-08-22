import React from 'react';
import { SearchForm } from './components/forms.js';
import { SertifikatsokSearchbutton } from './components/buttons.js';
import { SearchTabs } from './components/misc.js';
import { getCompanies } from './misc.js'
/* global window */

export class SearchPage extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            autocompleteData: {},
            opentab: 0,
            text: "Organisasjonsnummer eller -navn",
        };
        this.searchTimeout;
    }

    autocomplete(value) {
        if (this.state.opentab === 0) {
            if (this.searchTimeout) {
                window.clearTimeout(this.searchTimeout);
            }

            this.searchTimeout = window.setTimeout(async () => {
                const searchValue = value.split('\'').join('');
                if (searchValue.length > 3) {
                    const companies = await getCompanies(searchValue);
                    this.setState({
                        autocompleteData: companies,
                    });
                }
            }, 500);
        }
    }

    handletabChange(tabId) {
        let text;
        let autocompleteData;

        if (tabId === 0) {
            text = "Organisasjonsnummer eller -navn"
            autocompleteData = this.state.autocompleteData;
        } else if (tabId === 1) {
            text = "Fullt navn"
            autocompleteData = {}
        }

        this.setState({
            opentab: tabId,
            text: text,
            autocompleteData: autocompleteData,
        });
    }


    render() {
        return (
            <div className="card">
                <div className="card-tabs">
                    <SearchTabs
                        handleClick={(tabId) => this.handletabChange(tabId)}
                    />
                </div>
                <div className="card-content center">
                    <SearchForm
                        text={this.state.text}
                        data={this.state.autocompleteData}
                        onChange={(value) => this.autocomplete(value)}
                    />
                    <SertifikatsokSearchbutton
                        text="Søk"
                    />
                    &nbsp;
                    <SertifikatsokSearchbutton
                        text="Søk i test"
                    />
                </div>
            </div>
        )
    }
}
