import React, { Component } from 'react';
import { SearchPage } from './searchPage.js';
import { ResultPage } from './resultPage.js';
import { Header, Footer, HelpButton } from './common.js';
import { HjelpModal } from './components/modals.js'
/* global window */

class App extends Component {

    constructor(props) {
        super(props);
        this.state = {
            helpOpen: false,
        };
    }

    openHelp() {
        this.setState({
            helpOpen: true,
        });
    }

    closeHelp() {
        this.setState({
            helpOpen: false,
        });
    }

    render() {
        return (
            <div className="App">
                <Header />
                <main>
                    <div className="container" id="body-container">
                        {
                            window.location.search
                                ?
                                <ResultPage />
                                :
                                <SearchPage />
                        }
                    </div>
                </main>
                <HelpButton
                    onClick={() => this.openHelp()}
                />
                <Footer />
                <HjelpModal
                    remove={() => this.closeHelp()}
                    open={this.state.helpOpen}
                />
            </div>
        )
    }
}

export default App;
