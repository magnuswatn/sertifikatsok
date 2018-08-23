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
            searchFieldText: "Organisasjonsnummer eller -navn",
            inputText: "",
            searchText: "",
        };
        this.searchTimeout;
    }

    async doAutocomplete() {
        const searchValue = this.state.inputText.split('\'').join('');
        if (searchValue.length > 3) {
            const companies = await getCompanies(searchValue);
            this.setState({
                autocompleteData: companies,
            });
        }
    }

    doSearch(env) {
        const queryParams = {
            query: this.state.searchText,
            env: env,
            type: (this.state.opentab === 0) ? "enterprise" : "person"
        };

        const query = Object.keys(queryParams)
            .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(queryParams[k]))
            .join('&');

        window.location.search = query;
    }

    handleTextInput(text) {
        if (this.state.opentab === 0) {
            if (this.searchTimeout) {
                window.clearTimeout(this.searchTimeout);
            }

            this.searchTimeout = window.setTimeout(() => this.doAutocomplete(), 500);

        }
        this.setState({
            inputText: text,
            searchText: text,
        });
    }

    handleAutoComplete(value) {
        const re = /\((\d{9})\)/;
        const reResult = re.exec(value);

        this.setState({
            inputText: value,
            searchText: reResult[1],
        });
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
            searchFieldText: text,
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
                        labelText={this.state.searchFieldText}
                        inputText={this.state.inputText}
                        data={this.state.autocompleteData}
                        onChange={(value) => this.handleTextInput(value)}
                        onEnter={() => this.doSearch("prod")}
                        onKeyDown={(e) => this.handleKeyPress(e)}
                        onAutocomplete={(value) => this.handleAutoComplete(value)}
                    />
                    <SertifikatsokSearchbutton
                        text="Søk"
                        onClick={() => this.doSearch("prod")}
                    />
                    &nbsp;
                    <SertifikatsokSearchbutton
                        text="Søk i test"
                        onClick={() => this.doSearch("test")}
                    />
                </div>
            </div>
        )
    }
}
